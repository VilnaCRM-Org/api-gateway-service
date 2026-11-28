//! WebSocket and SSE streams through the gateway (Story 11.1, FR-61).
//!
//! On a route flagged `streaming` the pipeline authorizes the opening request like any other
//! request and registers the stream in the [`StreamRegistry`]. The upstream WebSocket upgrade goes
//! through `HyperUpstreamForwarder::forward_upgrade`, and after `101` the gateway splices both
//! directions of the upgraded connections ([`splice`]); an SSE response is relayed unbuffered by
//! [`sse`]. Nothing here compresses a stream or puts a response timeout on it.
//!
//! The registry never trusts the opening decision for good. [`Streams::scan`] runs on a short tick
//! and closes a stream when
//!
//! - its token expired (WebSocket 1008, SSE ended);
//! - it carried no traffic for `STREAM_IDLE_TIMEOUT` (WebSocket 1001);
//! - the earliest expiry of the assignments that authorized it passed and the stream, decided
//!   again on the current snapshot with the decision rule of the pipeline, is denied (1008). An
//!   assignment expiry produces no policy version, so nothing else would notice it;
//! - the pod may not allow new requests: its snapshot is gone (the pod fenced) or its proof is
//!   older than the hard bound, so a pod that must not admit requests keeps no old ones flowing
//!   (1013). `GOAWAY` never reaches an upgraded connection, so the registry closes them itself.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use iam_application::{FreshnessState, OpenStreams, ReevaluationBoard, StreamScope};
use iam_domain::{PolicyVersion, PolicyView};
use shared_domain::Clock;
use tokio::sync::watch;

pub use self::registry::{
    Activity, CloseReason, Grant, StreamHandle, StreamRecord, StreamRegistry, SubjectAtCap, Watched,
};
pub use self::splice::close_frame;

mod registry;
mod scan;
pub mod splice;
pub mod sse;

/// How often the registry is scanned for streams that must end.
pub const SCAN_INTERVAL: Duration = Duration::from_millis(100);

/// Completes when the stop flag is set or its sender is gone.
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    drop(shutdown.wait_for(|stopping| *stopping).await);
}

/// The numbers of the streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSettings {
    /// `STREAM_IDLE_TIMEOUT`: a stream without traffic for this long is closed.
    pub idle_timeout: Duration,
    /// The most streams one subject holds; the per-subject connection cap of Story 10.9.
    pub per_subject: usize,
}

/// What deciding a stream again on the current snapshot found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revalidated {
    /// The decision rule still allows the stream; the next assignment expiry to look at.
    Allowed {
        /// The earliest expiry that is still ahead, `None` when no assignment expires.
        next_expiry: Option<SystemTime>,
    },
    /// The decision rule denies the stream, or no decision could be made.
    Denied,
}

/// Decides a stream again on the current snapshot, with the decision rule of the pipeline.
#[async_trait::async_trait]
pub trait Redecision: std::fmt::Debug + Send + Sync {
    /// Decides `grant` again.
    async fn decide(&self, grant: &Grant) -> Revalidated;

    /// The version of the snapshot that is published now, `None` while there is none.
    fn published(&self) -> Option<i64>;
}

/// Whether the pod may keep its streams flowing.
pub trait StreamFence: std::fmt::Debug + Send + Sync {
    /// Whether the pod may not allow requests now: it fenced, or its proof is not fresh.
    fn closed(&self) -> bool;
}

/// The fence of a pod: the snapshot that was published and the verdict of its freshness state.
#[derive(Debug)]
pub struct PodFence {
    view: Arc<dyn PolicyView>,
    freshness: Arc<FreshnessState>,
}

impl PodFence {
    /// The fence over the published snapshot of `view` and the proof held by `freshness`.
    #[must_use]
    pub fn new(view: Arc<dyn PolicyView>, freshness: Arc<FreshnessState>) -> Self {
        Self { view, freshness }
    }
}

impl StreamFence for PodFence {
    fn closed(&self) -> bool {
        self.view.current().is_none() || !self.freshness.is_fresh()
    }
}

/// The streams of a pod: the registry and what keeps it honest.
#[derive(Debug)]
pub struct Streams {
    registry: Arc<StreamRegistry>,
    idle_timeout: Duration,
    clock: Arc<dyn Clock>,
    decider: OnceLock<Arc<dyn Redecision>>,
}

impl Streams {
    /// The streams of a pod with `settings`, judged on `clock`.
    #[must_use]
    pub fn new(settings: StreamSettings, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            registry: StreamRegistry::new(settings.per_subject),
            idle_timeout: settings.idle_timeout,
            clock,
            decider: OnceLock::new(),
        })
    }

    /// The registry of the open streams.
    #[must_use]
    pub const fn registry(&self) -> &Arc<StreamRegistry> {
        &self.registry
    }

    /// The time of the clock the expiries are judged on.
    #[must_use]
    pub fn now(&self) -> SystemTime {
        self.clock.now()
    }

    /// The clock the expiries are judged on.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Sets what decides a stream again. The first one stays; a second one is ignored.
    pub fn install(&self, decider: Arc<dyn Redecision>) {
        drop(self.decider.set(decider));
    }

    /// The check that follows the registration of the stream `id` (Story 11.2): a stream that
    /// the opening request authorized on a version below the published one is decided again at
    /// once on the published snapshot, and closed when that denies it. A stream that waits for
    /// this check holds back the record of finished re-evaluations.
    pub async fn admit(&self, id: u64) {
        let published = self.decider.get().and_then(|decider| decider.published());
        let authorized = self.registry.record(id).map(|record| record.version);
        match (authorized, published) {
            (Some(authorized), Some(published)) if authorized < published => {
                self.reevaluate_at(id, published).await;
            }
            _ => self.registry.admitted(id),
        }
    }

    /// Decides the stream `id` again with the decision rule of the pipeline: it stays open and is
    /// recorded as decided against `version` when the published snapshot allows it, and it is
    /// closed otherwise.
    async fn reevaluate_at(&self, id: u64, version: i64) {
        let Some(grant) = self.registry.grant(id) else {
            return;
        };
        let verdict = match self.decider.get() {
            Some(decider) => decider.decide(&grant).await,
            None => Revalidated::Denied,
        };
        match verdict {
            Revalidated::Allowed { next_expiry } => {
                self.registry.renew(id, next_expiry);
                self.registry.evaluated(id, version);
            }
            Revalidated::Denied => self.registry.close(id, CloseReason::Revoked),
        }
    }

    /// One pass over the registry: closes the streams of a pod that may not serve, and settles
    /// every stream whose token expired, that went idle or whose assignment expiry passed.
    pub async fn scan(&self, fence: &dyn StreamFence) {
        scan::run(self, fence).await;
    }

    /// Scans the registry every [`SCAN_INTERVAL`] until the stop flag is set.
    pub async fn watch(
        self: Arc<Self>,
        fence: Arc<dyn StreamFence>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut reported = 0;
        loop {
            tokio::select! {
                () = stopped(&mut shutdown) => return,
                () = tokio::time::sleep(SCAN_INTERVAL) => {}
            }
            self.scan(fence.as_ref()).await;
            reported = self.report(reported);
        }
    }

    /// Emits the metric event `streams_open` when the number of open streams changed.
    fn report(&self, reported: usize) -> usize {
        let open = self.registry.len();
        if open != reported {
            log_open(open);
        }
        open
    }
}

#[async_trait::async_trait]
impl OpenStreams for Streams {
    fn mark(&self) -> u64 {
        self.registry.mark()
    }

    fn select(&self, scope: &StreamScope) -> Vec<u64> {
        self.registry.select(scope)
    }

    async fn reevaluate(&self, stream: u64, version: PolicyVersion) {
        self.reevaluate_at(stream, version.value()).await;
    }

    fn settle(&self, mark: u64, version: PolicyVersion) {
        self.registry.settle(mark, version.value());
    }

    fn lagging(&self, version: PolicyVersion) -> Vec<u64> {
        self.registry.lagging(version.value())
    }

    fn finish(&self, version: PolicyVersion, board: &ReevaluationBoard) -> bool {
        self.registry.finish(version, board)
    }
}

fn log_open(streams: usize) {
    tracing::info!(metric = "streams_open", streams, "open streams");
}

#[cfg(test)]
mod tests;
