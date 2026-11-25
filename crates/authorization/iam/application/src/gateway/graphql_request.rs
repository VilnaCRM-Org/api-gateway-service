//! The analysis of the GraphQL documents of one request (Story 10.8, FR-8, FR-60).
//!
//! The composition root decodes the envelope of the body into [`GraphQlOperation`]s. The
//! [`GraphQlRequestAnalyzer`] turns them into the coordinates they select, against the type graphs
//! of the catalogue of the route's service: a document that was analysed before under the same
//! catalogue version comes from the [`DocumentCache`]; one that was not is charged to the parse
//! budget of the subject and parsed, on the request worker up to
//! [`BLOCKING_THRESHOLD_BYTES`] and on the bounded blocking pool above it, so that a large
//! document never holds a request worker.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{
    AnalyzedDocument, DecisionReason, DocumentCache, DocumentKey, GraphQlTarget, ServiceCatalog,
};
use tokio::time::Instant;

use crate::required_key_resolver::{analyze_versions, refusal_reason};

/// The size above which a document is parsed on the blocking pool: 8 KB.
pub const BLOCKING_THRESHOLD_BYTES: usize = 8 * 1024;

/// The most operations of one batch.
pub const MAX_BATCH_OPERATIONS: usize = 10;

/// The length of the window of the parse budget.
const BUDGET_WINDOW: Duration = Duration::from_secs(1);

/// The number of subjects after which the budget drops the windows that have ended.
const PRUNE_ABOVE: usize = 4_096;

/// One operation of a GraphQL request, as the envelope decoder read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlOperation {
    /// The document text.
    pub document: String,
    /// The `operationName` member, when the request names one.
    pub operation_name: Option<String>,
}

/// What a subject may spend on parsing per second (CONFIG).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseBudgetSettings {
    /// The cache misses a subject may cause per second.
    pub misses_per_second: u32,
    /// The bytes of document text a subject may have parsed per second.
    pub bytes_per_second: u64,
}

impl Default for ParseBudgetSettings {
    fn default() -> Self {
        Self {
            misses_per_second: 20,
            bytes_per_second: 1_048_576,
        }
    }
}

/// The spending of one subject in its current window.
#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    misses: u32,
    bytes: u64,
}

impl Window {
    const fn opened(now: Instant) -> Self {
        Self {
            started: now,
            misses: 0,
            bytes: 0,
        }
    }

    fn ended(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= BUDGET_WINDOW
    }
}

/// The per-subject budget of cache misses and parsed bytes, in fixed windows of one second on the
/// tokio clock, so paused time controls it.
#[derive(Debug)]
pub struct ParseBudget {
    settings: ParseBudgetSettings,
    windows: Mutex<HashMap<String, Window>>,
}

impl ParseBudget {
    /// A budget with `settings` and every subject unspent.
    #[must_use]
    pub fn new(settings: ParseBudgetSettings) -> Self {
        Self {
            settings,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Charges one miss of `bytes` to `subject`; `false` when that would pass either limit, in which
    /// case nothing is charged.
    pub fn charge(&self, subject: &str, bytes: usize) -> bool {
        let now = Instant::now();
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        spend(&mut windows, self.settings, (subject, bytes), now)
    }
}

/// Charges one miss of `bytes` to the window of `subject` at `now`, in a window of its own once the
/// previous one has ended.
fn spend(
    windows: &mut HashMap<String, Window>,
    settings: ParseBudgetSettings,
    (subject, bytes): (&str, u64),
    now: Instant,
) -> bool {
    if windows.len() >= PRUNE_ABOVE {
        windows.retain(|_, window| !window.ended(now));
    }
    let window = windows
        .entry(subject.to_owned())
        .or_insert_with(|| Window::opened(now));
    if window.ended(now) {
        *window = Window::opened(now);
    }
    let misses = window.misses.saturating_add(1);
    let spent = window.bytes.saturating_add(bytes);
    if misses > settings.misses_per_second || spent > settings.bytes_per_second {
        return false;
    }
    window.misses = misses;
    window.bytes = spent;
    true
}

/// Where a document was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseSite {
    /// On the request worker, inline.
    Worker,
    /// On the bounded blocking pool.
    BlockingPool,
}

/// A hook that sees every parse; tests use it to prove where a document was parsed.
pub trait ParseObserver: std::fmt::Debug + Send + Sync {
    /// A document of `bytes` bytes is being parsed at `site`; the call runs on the thread that
    /// parses.
    fn parsed(&self, site: ParseSite, bytes: usize);
}

/// What analysing the operations of a request found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Analysis {
    /// The coordinates of every operation, merged.
    Analyzed(AnalyzedDocument),
    /// A document cannot be authorized; the reason is the one the denial carries.
    Refused(DecisionReason),
    /// The subject is over its parse budget.
    RateLimited,
    /// The analysis could not run to its end.
    Unavailable,
}

/// Analyses the documents of a request, caches the result and bounds the work a subject may cause.
#[derive(Debug)]
pub struct GraphQlRequestAnalyzer {
    cache: Arc<dyn DocumentCache>,
    budget: ParseBudget,
    observer: Option<Arc<dyn ParseObserver>>,
    lookups: AtomicU64,
    hits: AtomicU64,
}

impl GraphQlRequestAnalyzer {
    /// An analyzer over `cache` that spends the budget of `settings`.
    #[must_use]
    pub fn new(cache: Arc<dyn DocumentCache>, settings: ParseBudgetSettings) -> Self {
        Self {
            cache,
            budget: ParseBudget::new(settings),
            observer: None,
            lookups: AtomicU64::new(0),
            hits: AtomicU64::new(0),
        }
    }

    /// The same analyzer reporting every parse to `observer`.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn ParseObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Analyses `operations` against the type graphs of `catalog` for `subject`.
    pub async fn analyze(
        &self,
        catalog: &ServiceCatalog,
        subject: &str,
        operations: &[GraphQlOperation],
    ) -> Analysis {
        if operations.is_empty() {
            return Analysis::Refused(DecisionReason::MalformedOperation);
        }
        let mut merged = AnalyzedDocument::default();
        for operation in operations {
            match self.analyze_one(catalog, subject, operation).await {
                Analysis::Analyzed(analyzed) => merged = merge(&merged, &analyzed),
                refused
                @ (Analysis::Refused(_) | Analysis::RateLimited | Analysis::Unavailable) => {
                    return refused;
                }
            }
        }
        Analysis::Analyzed(merged)
    }

    async fn analyze_one(
        &self,
        catalog: &ServiceCatalog,
        subject: &str,
        operation: &GraphQlOperation,
    ) -> Analysis {
        let service = catalog.service();
        let key = DocumentKey::of(
            &operation.document,
            operation.operation_name.as_deref(),
            catalog.policy_version(),
        );
        if let Some(found) = self.cache.get(service, key, &operation.document) {
            self.looked_up(true);
            return Analysis::Analyzed(found);
        }
        self.looked_up(false);
        if !self.budget.charge(subject, operation.document.len()) {
            return Analysis::RateLimited;
        }
        match self.parse(catalog, operation).await {
            Some(Ok(analyzed)) if usable(&analyzed) => {
                self.cache
                    .insert(service, key, &operation.document, analyzed.clone());
                Analysis::Analyzed(analyzed)
            }
            Some(Ok(_empty)) => Analysis::Refused(DecisionReason::MalformedOperation),
            Some(Err(reason)) => Analysis::Refused(reason),
            None => Analysis::Unavailable,
        }
    }

    /// Parses the document where its size says; `None` when the blocking task did not finish.
    async fn parse(
        &self,
        catalog: &ServiceCatalog,
        operation: &GraphQlOperation,
    ) -> Option<Result<AnalyzedDocument, DecisionReason>> {
        let target =
            GraphQlTarget::new(operation.document.clone(), operation.operation_name.clone());
        let bytes = operation.document.len();
        let observer = self.observer.clone();
        if bytes <= BLOCKING_THRESHOLD_BYTES {
            observe(observer.as_ref(), ParseSite::Worker, bytes);
            return Some(resolve(&target, catalog));
        }
        let catalog = catalog.clone();
        tokio::task::spawn_blocking(move || {
            observe(observer.as_ref(), ParseSite::BlockingPool, bytes);
            resolve(&target, &catalog)
        })
        .await
        .ok()
    }

    /// Counts one cache lookup and emits the metric event `graphql_document_cache_hit_ratio`.
    fn looked_up(&self, hit: bool) {
        let lookups = self
            .lookups
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let hits = self.hits.fetch_add(u64::from(hit), Ordering::Relaxed);
        let hits = hits.saturating_add(u64::from(hit));
        emit_hit_ratio(hits, lookups);
    }
}

/// The metric event `graphql_document_cache_hit_ratio`.
fn emit_hit_ratio(hits: u64, lookups: u64) {
    let value = ratio(hits, lookups);
    tracing::info!(
        target: "metrics",
        metric = "graphql_document_cache_hit_ratio",
        value,
    );
}

fn observe(observer: Option<&Arc<dyn ParseObserver>>, site: ParseSite, bytes: usize) {
    if let Some(observer) = observer {
        observer.parsed(site, bytes);
    }
}

/// `hits` over `lookups`, both scaled down together until they fit an `f64` conversion exactly.
fn ratio(hits: u64, lookups: u64) -> f64 {
    let (mut hits, mut lookups) = (hits, lookups);
    while lookups > u64::from(u32::MAX) {
        hits >>= 1;
        lookups >>= 1;
    }
    let hits = u32::try_from(hits).unwrap_or(u32::MAX);
    let lookups = u32::try_from(lookups).unwrap_or(u32::MAX);
    if lookups == 0 {
        0.0
    } else {
        f64::from(hits) / f64::from(lookups)
    }
}

/// A document that selects at least one coordinate or is an introspection query; any other
/// document, `{ __typename }` for one, has nothing to authorize.
fn usable(analyzed: &AnalyzedDocument) -> bool {
    !analyzed.coordinates().is_empty() || analyzed.introspection()
}

/// Analyses `target` against every active version of the catalogue and merges what the versions
/// that accept it found; the reason of the refusal when none accepts it.
fn resolve(
    target: &GraphQlTarget,
    catalog: &ServiceCatalog,
) -> Result<AnalyzedDocument, DecisionReason> {
    let (resolved, refusals) = analyze_versions(target, catalog.type_graphs());
    if resolved.is_empty() {
        return Err(refusal_reason(&refusals));
    }
    Ok(resolved
        .iter()
        .fold(AnalyzedDocument::default(), |merged, analyzed| {
            merge(&merged, analyzed)
        }))
}

/// The coordinates of both documents and whether either one is an introspection query.
fn merge(left: &AnalyzedDocument, right: &AnalyzedDocument) -> AnalyzedDocument {
    let coordinates = left.coordinates().union(right.coordinates());
    AnalyzedDocument::new(coordinates, left.introspection() || right.introspection())
}

#[cfg(test)]
mod tests;
