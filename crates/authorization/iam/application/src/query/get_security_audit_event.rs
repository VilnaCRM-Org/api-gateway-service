//! Reads one security audit record and audits the read (FR-52).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditSummary, RepositoryError, SecurityAuditEventId, SecurityAuditLog,
    StoredSecurityAuditEvent,
};
use shared_domain::{Clock, Query, QueryHandler, UuidGenerator};

use crate::error::IamError;
use crate::security_audit_reads::{ReadAudit, ReadRecord};

/// The audited action of the read of one record.
pub const AUDIT_ACTION: &str = "security_audit.read";

/// Asks for the audit record with the identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSecurityAuditEventQuery {
    /// Who asks; the read is recorded in the log under this actor.
    pub actor: ActorRef,
    /// The record to read.
    pub id: SecurityAuditEventId,
}

impl Query for GetSecurityAuditEventQuery {
    type Output = Option<StoredSecurityAuditEvent>;
    type Error = IamError;
    const NAME: &'static str = "GetSecurityAuditEventQuery";
}

/// Handles [`GetSecurityAuditEventQuery`]: the record with its place in the chain, or none when it
/// is unknown. A read that finds the record is audited; one that finds none is not.
#[derive(Debug)]
pub struct GetSecurityAuditEventQueryHandler {
    log: Arc<dyn SecurityAuditLog>,
    audit: ReadAudit,
}

impl GetSecurityAuditEventQueryHandler {
    /// A handler over the audit log, with the `Clock` and `UuidGenerator` ports that stamp the
    /// record of the read.
    #[must_use]
    pub fn new(
        log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        let audit = ReadAudit::new(Arc::clone(&log), clock, ids);
        Self { log, audit }
    }

    async fn get(
        &self,
        query: GetSecurityAuditEventQuery,
    ) -> Result<Option<StoredSecurityAuditEvent>, IamError> {
        let record = match self.log.find_by_id(query.id).await {
            Ok(record) => record,
            Err(RepositoryError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let target_id = query.id.to_string();
        let summary = AuditSummary::new(&format!("seq={}", record.seq()))?;
        self.audit
            .record(ReadRecord {
                actor: &query.actor,
                action: AUDIT_ACTION,
                target_id: &target_id,
                summary,
            })
            .await?;
        Ok(Some(record))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetSecurityAuditEventQuery> for GetSecurityAuditEventQueryHandler {
    async fn handle(
        &self,
        query: GetSecurityAuditEventQuery,
    ) -> Result<Option<StoredSecurityAuditEvent>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
