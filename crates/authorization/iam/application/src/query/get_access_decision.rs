//! Reads one access decision from the log store and audits the read (FR-51, FR-54).

use std::sync::Arc;

use iam_domain::{AccessLogEntry, AccessLogQuery, ActorRef, AuditSummary, SecurityAuditLog};
use shared_domain::{Clock, Query, QueryHandler, Uuid, UuidGenerator};

use super::get_access_decisions::{TARGET_TYPE, log_seconds};
use crate::error::IamError;
use crate::security_audit_reads::{ReadAudit, ReadRecord};

/// The audited action of the read of one decision.
pub const AUDIT_ACTION: &str = "access_log.read";

/// Asks for the access decision with the identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAccessDecisionQuery {
    /// Who asks; the read is recorded in the audit log under this actor.
    pub actor: ActorRef,
    /// The id of the decision, a UUID v7.
    pub id: Uuid,
}

impl Query for GetAccessDecisionQuery {
    type Output = Option<AccessLogEntry>;
    type Error = IamError;
    const NAME: &'static str = "GetAccessDecisionQuery";
}

/// Handles [`GetAccessDecisionQuery`]: the decision, or none when the window around the timestamp
/// of its id holds none. A read that finds the decision is audited; one that finds none is not.
#[derive(Debug)]
pub struct GetAccessDecisionQueryHandler {
    store: Arc<dyn AccessLogQuery>,
    audit: ReadAudit,
    clock: Arc<dyn Clock>,
}

impl GetAccessDecisionQueryHandler {
    /// A handler over the log store, with the audit log and the `Clock` and `UuidGenerator` ports
    /// that stamp the record of the read.
    #[must_use]
    pub fn new(
        store: Arc<dyn AccessLogQuery>,
        audit_log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        let audit = ReadAudit::new(audit_log, Arc::clone(&clock), ids);
        Self {
            store,
            audit,
            clock,
        }
    }

    async fn get(&self, query: GetAccessDecisionQuery) -> Result<Option<AccessLogEntry>, IamError> {
        let started = self.clock.now();
        let answer = self.store.find(query.id).await;
        log_seconds(&*self.clock, started, "find", answer.as_ref().err());
        let Some(entry) = answer? else {
            return Ok(None);
        };
        let target_id = query.id.to_string();
        let summary = AuditSummary::new(&format!("timestamp_ns={}", entry.timestamp_nanos))?;
        self.audit
            .record_about(
                TARGET_TYPE,
                ReadRecord {
                    actor: &query.actor,
                    action: AUDIT_ACTION,
                    target_id: &target_id,
                    summary,
                },
            )
            .await?;
        Ok(Some(entry))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetAccessDecisionQuery> for GetAccessDecisionQueryHandler {
    async fn handle(
        &self,
        query: GetAccessDecisionQuery,
    ) -> Result<Option<AccessLogEntry>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
