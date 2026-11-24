//! Searches the security audit log and audits the search (FR-52).

use std::sync::Arc;

use iam_domain::{
    ActorRef, SecurityAuditFilter, SecurityAuditLog, SecurityAuditSearch, StoredSecurityAuditEvent,
};
use shared_domain::{Clock, Query, QueryHandler, UuidGenerator};

use crate::error::IamError;
use crate::security_audit_reads::{ReadAudit, ReadRecord, SEARCH_TARGET_ID, search_summary};

/// The largest page of audit records.
pub const MAX_PAGE_SIZE: u32 = 100;

/// The audited action of a search.
pub const AUDIT_ACTION: &str = "security_audit.list";

/// Asks for one page of the audit records that meet a filter, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSecurityAuditEventsQuery {
    /// Who asks; the search is recorded in the log under this actor.
    pub actor: ActorRef,
    /// The conditions the records must meet.
    pub filter: SecurityAuditFilter,
    /// The largest number of records of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The sequence number of the last record of the previous page; none for the first page.
    pub before_seq: Option<i64>,
}

/// One page of audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditEventPage {
    /// The records of the page, newest first.
    pub events: Vec<StoredSecurityAuditEvent>,
    /// The cursor of the next page: the sequence number of the last record of this one; none when
    /// no older record follows.
    pub next_before: Option<i64>,
}

impl Query for GetSecurityAuditEventsQuery {
    type Output = SecurityAuditEventPage;
    type Error = IamError;
    const NAME: &'static str = "GetSecurityAuditEventsQuery";
}

/// Handles [`GetSecurityAuditEventsQuery`].
///
/// It reads one record more than the page holds, to know whether an older page follows without a
/// second query, and appends the record of the search once the page is read, so that a search
/// that cannot be audited is not served and a search never finds its own record.
#[derive(Debug)]
pub struct GetSecurityAuditEventsQueryHandler {
    log: Arc<dyn SecurityAuditLog>,
    audit: ReadAudit,
}

impl GetSecurityAuditEventsQueryHandler {
    /// A handler over the audit log, with the `Clock` and `UuidGenerator` ports that stamp the
    /// record of the search.
    #[must_use]
    pub fn new(
        log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        let audit = ReadAudit::new(Arc::clone(&log), clock, ids);
        Self { log, audit }
    }

    async fn search(
        &self,
        query: GetSecurityAuditEventsQuery,
    ) -> Result<SecurityAuditEventPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let summary = search_summary(&query.filter, limit, query.before_seq)?;
        let read = SecurityAuditSearch {
            filter: query.filter,
            before_seq: query.before_seq,
            limit: limit.saturating_add(1),
        };
        let mut events = self.log.search(&read).await?;
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_before = events
            .get(size.saturating_sub(1))
            .filter(|_last| events.len() > size)
            .map(StoredSecurityAuditEvent::seq);
        events.truncate(size);
        self.audit
            .record(ReadRecord {
                actor: &query.actor,
                action: AUDIT_ACTION,
                target_id: SEARCH_TARGET_ID,
                summary,
            })
            .await?;
        Ok(SecurityAuditEventPage {
            events,
            next_before,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetSecurityAuditEventsQuery> for GetSecurityAuditEventsQueryHandler {
    async fn handle(
        &self,
        query: GetSecurityAuditEventsQuery,
    ) -> Result<SecurityAuditEventPage, IamError> {
        self.search(query).await
    }
}

#[cfg(test)]
mod tests;
