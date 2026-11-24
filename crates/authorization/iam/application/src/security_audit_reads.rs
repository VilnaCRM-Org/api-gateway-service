//! The audit record that every successful read of the security audit log leaves in the log
//! itself (FR-52).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts, SecurityAuditFilter, SecurityAuditLog,
};
use shared_domain::{Clock, UuidGenerator};

use crate::error::IamError;

/// The target type of the record of a read.
pub(crate) const TARGET_TYPE: &str = "security_audit_event";

/// The target id of the record of a search, which reads no single record.
pub(crate) const SEARCH_TARGET_ID: &str = "query";

/// What the summary says when the conditions of a search cannot be written down, for instance
/// because a value has the shape of a token.
const UNSUMMARISED: &str = "filter=unsummarised";

/// Appends the record of a read to the audit log.
#[derive(Debug, Clone)]
pub(crate) struct ReadAudit {
    log: Arc<dyn SecurityAuditLog>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn UuidGenerator>,
}

/// What a read says about itself.
#[derive(Debug)]
pub(crate) struct ReadRecord<'a> {
    /// Who read.
    pub actor: &'a ActorRef,
    /// The audited action, such as `security_audit.list`.
    pub action: &'static str,
    /// The id of the target: the record that was read, or [`SEARCH_TARGET_ID`].
    pub target_id: &'a str,
    /// The conditions of the read, as a summary.
    pub summary: AuditSummary,
}

impl ReadAudit {
    /// An audit over the log, with the `Clock` and `UuidGenerator` ports.
    pub(crate) fn new(
        log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self { log, clock, ids }
    }

    /// Appends the committed record of the read.
    ///
    /// # Errors
    ///
    /// [`IamError::Storage`] when the log cannot be written, so that a read that cannot be audited
    /// is not served; [`IamError::Internal`] when a value breaks an invariant of the domain.
    pub(crate) async fn record(&self, read: ReadRecord<'_>) -> Result<(), IamError> {
        let ReadRecord {
            actor,
            action,
            target_id,
            summary,
        } = read;
        let event = SecurityAuditEvent::record(SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.ids.generate()),
            occurred_at: self.clock.now(),
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(action)?,
            target: AuditTarget::new(TARGET_TYPE, target_id)?,
            scope: None,
            before: None,
            after: Some(summary),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        })?;
        self.log.append_batch(&[event]).await?;
        Ok(())
    }
}

/// The summary of a search: its page size, its cursor and every condition of its filter.
///
/// # Errors
///
/// [`IamError::Internal`] only when even the fixed summary of last resort is refused.
pub(crate) fn search_summary(
    filter: &SecurityAuditFilter,
    limit: u32,
    before_seq: Option<i64>,
) -> Result<AuditSummary, IamError> {
    let parts = [
        Some(format!("limit={limit}")),
        before_seq.map(|before| format!("before={before}")),
        filter.since_micros().map(|from| format!("from={from}")),
        filter.until_micros().map(|until| format!("until={until}")),
        filter.actor().map(|actor| format!("actor={actor}")),
        filter.action().map(|action| format!("action={action}")),
        filter
            .target_type()
            .map(|target_type| format!("target_type={target_type}")),
        filter
            .target_id()
            .map(|target_id| format!("target_id={target_id}")),
        filter
            .outcome()
            .map(|outcome| format!("outcome={}", outcome.as_str())),
    ];
    let text = parts.into_iter().flatten().collect::<Vec<_>>().join(";");
    Ok(AuditSummary::new(&text).or_else(|_refused| AuditSummary::new(UNSUMMARISED))?)
}

#[cfg(test)]
mod tests;
