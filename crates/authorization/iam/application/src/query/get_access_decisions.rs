//! Searches the access decisions in the log store and audits the search (FR-51, FR-54, NFR-44).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessLogCursor, AccessLogEntry, AccessLogFilter, AccessLogQuery, AccessLogQueryError,
    AccessLogRange, AccessLogSearch, ActorRef, AuditSummary, CursorSeal, InvalidAccessLogRange,
    MAX_CURSOR_RETURNED, SecurityAuditLog,
};
use shared_domain::{Clock, Query, QueryHandler, UuidGenerator};

use crate::error::IamError;
use crate::security_audit_reads::{ReadAudit, ReadRecord};

/// The largest page of access decisions.
pub const MAX_PAGE_SIZE: u32 = iam_domain::MAX_ACCESS_LOG_PAGE;

/// The audited action of a search.
pub const AUDIT_ACTION: &str = "access_log.list";

/// The target type of the record of a read of the access decisions.
pub(crate) const TARGET_TYPE: &str = "access_decision";

/// The target id of the record of a search, which reads no single decision.
pub(crate) const SEARCH_TARGET_ID: &str = "query";

/// What the summary says when the conditions of a search cannot be written down.
const UNSUMMARISED: &str = "filter=unsummarised";

/// Asks for one page of the access decisions in a time range that meet a filter, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAccessDecisionsQuery {
    /// Who asks; the search is recorded in the audit log under this actor.
    pub actor: ActorRef,
    /// The start of the time range.
    pub from: SystemTime,
    /// The end of the time range, not included.
    pub until: SystemTime,
    /// The conditions the decisions must meet.
    pub filter: AccessLogFilter,
    /// The largest number of decisions of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The `nextCursor` token of the previous page, as the client handed it back; none for the
    /// first page. The handler opens it with its [`CursorSeal`] and refuses a token it did not
    /// issue.
    pub cursor: Option<String>,
}

/// One page of access decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecisionPage {
    /// The decisions of the page, newest first.
    pub entries: Vec<AccessLogEntry>,
    /// The sealed cursor token of the next page; none when no older decision follows.
    pub next: Option<String>,
}

impl Query for GetAccessDecisionsQuery {
    type Output = AccessDecisionPage;
    type Error = IamError;
    const NAME: &'static str = "GetAccessDecisionsQuery";
}

/// Handles [`GetAccessDecisionsQuery`].
///
/// It checks that the range is within `ACCESS_LOG_QUERY_MAX_RANGE`, reads one decision more than
/// the page holds to know whether an older page follows, and appends the record of the search to
/// the audit log once the page is read, so that a search that cannot be audited is not served. A
/// query that the log store cannot answer in time returns no page.
#[derive(Debug)]
pub struct GetAccessDecisionsQueryHandler {
    store: Arc<dyn AccessLogQuery>,
    audit: ReadAudit,
    clock: Arc<dyn Clock>,
    max_range: Duration,
    seal: Arc<dyn CursorSeal>,
}

impl GetAccessDecisionsQueryHandler {
    /// A handler over the log store, with the audit log, the `Clock` and `UuidGenerator` ports
    /// that stamp the record of the search, and the paging rules: the longest range that may be
    /// queried and the seal that protects the cursors it issues.
    #[must_use]
    pub fn new(
        store: Arc<dyn AccessLogQuery>,
        audit_log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
        (max_range, seal): (Duration, Arc<dyn CursorSeal>),
    ) -> Self {
        let audit = ReadAudit::new(audit_log, Arc::clone(&clock), ids);
        Self {
            store,
            audit,
            clock,
            max_range,
            seal,
        }
    }

    /// The cursor that the token of a query names: a token this handler's seal did not issue, or
    /// one that claims more returned entries than a cursor may, is a 422 on `after`.
    fn cursor_of(&self, token: Option<&str>) -> Result<Option<AccessLogCursor>, IamError> {
        token
            .map(|token| {
                AccessLogCursor::opened(token, &*self.seal)
                    .filter(|cursor| cursor.returned <= MAX_CURSOR_RETURNED)
                    .ok_or_else(|| {
                        IamError::invalid_property(
                            "after",
                            "This value is not a valid cursor.",
                            "format",
                        )
                    })
            })
            .transpose()
    }

    async fn search(&self, query: GetAccessDecisionsQuery) -> Result<AccessDecisionPage, IamError> {
        let range = AccessLogRange::new(query.from, query.until, self.max_range)
            .map_err(range_violation)?;
        let cursor = self.cursor_of(query.cursor.as_deref())?;
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let summary = search_summary(&query, cursor, limit)?;
        let read = AccessLogSearch {
            range,
            filter: query.filter,
            cursor,
            limit: limit.saturating_add(1),
        };
        let started = self.clock.now();
        let answer = self.store.search(&read).await;
        log_seconds(&*self.clock, started, "search", answer.as_ref().err());
        let mut entries = answer?;
        let next = next_cursor(&mut entries, limit, cursor).map(|next| next.sealed(&*self.seal));
        self.audit
            .record_about(
                TARGET_TYPE,
                ReadRecord {
                    actor: &query.actor,
                    action: AUDIT_ACTION,
                    target_id: SEARCH_TARGET_ID,
                    summary,
                },
            )
            .await?;
        Ok(AccessDecisionPage { entries, next })
    }
}

/// Cuts `entries` to the page and returns the cursor of the next page: the one decision beyond the
/// page says an older page follows.
fn next_cursor(
    entries: &mut Vec<AccessLogEntry>,
    limit: u32,
    previous: Option<AccessLogCursor>,
) -> Option<AccessLogCursor> {
    let size = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = entries.len() > size;
    entries.truncate(size);
    let last = entries.last().map(|entry| entry.timestamp_nanos)?;
    let at_last = entries
        .iter()
        .filter(|entry| entry.timestamp_nanos == last)
        .count();
    more.then(|| AccessLogCursor::after(last, u32::try_from(at_last).unwrap_or(u32::MAX), previous))
}

/// The violation of a range that cannot be queried.
fn range_violation(error: InvalidAccessLogRange) -> IamError {
    IamError::invalid_property(error.property_path(), &error.to_string(), error.code())
}

/// The summary of a search: its page size, its cursor, its range and every condition of its
/// filter.
///
/// # Errors
///
/// [`IamError::Internal`] only when even the fixed summary of last resort is refused.
fn search_summary(
    query: &GetAccessDecisionsQuery,
    cursor: Option<AccessLogCursor>,
    limit: u32,
) -> Result<AuditSummary, IamError> {
    let filter = &query.filter;
    let parts = [
        Some(format!("limit={limit}")),
        cursor.map(|cursor| format!("cursor={}", cursor.encode())),
        Some(format!("from={}", seconds(query.from))),
        Some(format!("until={}", seconds(query.until))),
        filter
            .subject_id
            .as_ref()
            .map(|subject| format!("subject_id={subject}")),
        filter
            .subject_kind
            .map(|kind| format!("subject_kind={}", kind.as_str())),
        filter
            .decision
            .map(|decision| format!("decision={}", decision.as_str())),
        filter.reason.map(|reason| format!("reason={reason}")),
        filter
            .upstream
            .as_ref()
            .map(|upstream| format!("upstream={upstream}")),
        filter.route_id.map(|route| format!("route_id={route}")),
        filter.status.map(|status| format!("status={status}")),
    ];
    let text = parts.into_iter().flatten().collect::<Vec<_>>().join(";");
    Ok(AuditSummary::new(&text).or_else(|_refused| AuditSummary::new(UNSUMMARISED))?)
}

/// Whole seconds since 1970; zero before it.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Emits the metric event `access_log_query_seconds`: how long the log store took, with the kind
/// of query and how it ended.
pub(crate) fn log_seconds(
    clock: &dyn Clock,
    started: SystemTime,
    kind: &'static str,
    failure: Option<&AccessLogQueryError>,
) {
    let seconds = clock
        .now()
        .duration_since(started)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let outcome = outcome_of(failure);
    tracing::info!(
        metric = "access_log_query_seconds",
        seconds,
        kind,
        outcome,
        "duration of a query of the access log store"
    );
}

/// The word that says how a query ended.
const fn outcome_of(failure: Option<&AccessLogQueryError>) -> &'static str {
    match failure {
        None => "ok",
        Some(AccessLogQueryError::Timeout) => "timeout",
        Some(AccessLogQueryError::Unavailable) => "unavailable",
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetAccessDecisionsQuery> for GetAccessDecisionsQueryHandler {
    async fn handle(&self, query: GetAccessDecisionsQuery) -> Result<AccessDecisionPage, IamError> {
        self.search(query).await
    }
}

#[cfg(test)]
mod tests;
