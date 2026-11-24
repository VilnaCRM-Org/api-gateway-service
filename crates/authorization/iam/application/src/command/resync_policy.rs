//! Republishes the complete current policy as a new log epoch (FR-1, FR-78).
//!
//! The handler starts the resync in one transaction: it moves the log epoch on, raises the policy
//! version above every version the state topic holds, records the pending bulk operation of kind
//! `resync` and writes the audit record and `iam.policy.resynced`. The `BulkOperationRunner` then
//! publishes the state of every entity under the new log epoch, chunk by chunk (see
//! [`ResyncChunkCommitter`](crate::resync_chunks::ResyncChunkCommitter)).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, BulkKind, BulkOperation,
    BulkOperationId, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, EpochChange,
    EventEnvelope, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    PolicyEpochRepository, PolicyResynced, PolicyStateInventory, PolicyVersion, ResyncStart,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
};
use shared_application::http::Violation;
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;
use crate::policy_topic_head::PolicyTopicHead;

/// The audited action of a resync.
const AUDIT_ACTION: &str = "policy.resync";

/// The command that resyncs the policy as `actor` for `reason`.
///
/// The caller chooses the identifier of the change, which is also the identifier of the bulk
/// operation, so that it can read the operation after the command returned; the command returns no
/// data.
#[derive(Debug, Clone)]
pub struct ResyncPolicyCommand {
    /// The identifier of the change, the key of its receipt and the id of the bulk operation.
    pub change_id: ChangeId,
    /// Who resyncs the policy.
    pub actor: ActorRef,
    /// Why the operator resyncs: one line, 1 to 500 characters.
    pub reason: String,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for ResyncPolicyCommand {
    type Error = IamError;
    const NAME: &'static str = "ResyncPolicyCommand";
}

/// The ports of the handler.
#[derive(Debug, Clone)]
pub struct ResyncPolicyPorts {
    /// The policy version and the log epoch that the resync starts from.
    pub epochs: Arc<dyn PolicyEpochRepository>,
    /// Counts the entities the resync publishes.
    pub inventory: Arc<dyn PolicyStateInventory>,
    /// Reads the highest version of the state topic.
    pub topic: PolicyTopicHead,
    /// Commits the start of the resync as one change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The time of the resync.
    pub clock: Arc<dyn Clock>,
    /// The identifiers of the event and the audit record.
    pub ids: Arc<dyn UuidGenerator>,
}

/// Handles [`ResyncPolicyCommand`].
///
/// The versions of the resync continue above both the PostgreSQL version and the highest `__head`
/// version of the topic, so that no reader sees a version regression. A resync takes the lock of
/// the policy epoch row like every versioned change, so a change that started from another log
/// epoch is refused as a conflict.
#[derive(Debug)]
pub struct ResyncPolicyCommandHandler {
    ports: ResyncPolicyPorts,
}

impl ResyncPolicyCommandHandler {
    /// A handler over its ports.
    #[must_use]
    pub const fn new(ports: ResyncPolicyPorts) -> Self {
        Self { ports }
    }

    async fn resync(&self, command: ResyncPolicyCommand) -> Result<(), IamError> {
        let reason = reason_of(&command.reason)?;
        let epoch = self.ports.epochs.current().await?;
        let topic = self.ports.topic.highest_version().await?;
        let stored = epoch.version();
        let floor = topic.map_or(stored, |topic| topic.max(stored));
        let total = self.ports.inventory.count().await?;
        let now = self.ports.clock.now();
        let id = BulkOperationId::from_uuid(command.change_id.as_uuid());
        let operation =
            BulkOperation::pending(id, BulkKind::Resync, total, command.actor.clone(), now)
                .map_err(|_invalid| IamError::Conflict)?;
        let change = EpochChange::new(epoch.log_epoch(), floor)?;
        let resynced = PolicyResynced {
            event_id: self.ports.ids.generate(),
            bulk_operation_id: id,
            log_epoch: change.to(),
            from_version: epoch.version(),
            to_version: next_version(floor)?,
            reason: reason.clone(),
            actor: command.actor.clone(),
            occurred_at: now,
        };
        let audit = self.audit(&command, &resynced, total)?;
        let start = ResyncStart::new(change, operation.parts().clone());
        let parts = IamChangeParts {
            change_id: command.change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::StartResync(Box::new(start))],
            events: vec![EventEnvelope::of(&resynced)?],
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: command.idempotency,
        };
        let change = IamChange::new(parts)?;
        self.ports
            .unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The committed audit record of the resync: the epoch and version before it, and the epoch,
    /// the first version, the records and the reason after it.
    fn audit(
        &self,
        command: &ResyncPolicyCommand,
        resynced: &PolicyResynced,
        total: u64,
    ) -> Result<SecurityAuditEvent, IamError> {
        let held = format!(
            "logEpoch={} version={}",
            resynced.log_epoch.value().saturating_sub(1),
            resynced.from_version.value()
        );
        let ended = format!(
            "logEpoch={} firstVersion={} records={total} reason={}",
            resynced.log_epoch.value(),
            resynced.to_version.value(),
            resynced.reason.as_str()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.ports.ids.generate()),
            occurred_at: resynced.occurred_at,
            actor: command.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("bulk_operation", &resynced.bulk_operation_id.to_string())?,
            scope: None,
            before: Some(AuditSummary::new(&held)?),
            after: Some(AuditSummary::new(&ended)?),
            idempotency_key: command
                .idempotency
                .as_ref()
                .map(|request| request.key.clone()),
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The reason as an audit text; one that the audit log would refuse (a control character, or a
/// word shaped like a token) is an invalid `reason`.
fn reason_of(text: &str) -> Result<AuditSummary, IamError> {
    AuditSummary::new(text.trim()).map_err(|_invalid| {
        IamError::Invalid(vec![Violation {
            property_path: "reason".to_owned(),
            message: "This value must be one line of text that holds no credential.".to_owned(),
            code: "format".to_owned(),
        }])
    })
}

/// The version after `version`.
fn next_version(version: PolicyVersion) -> Result<PolicyVersion, IamError> {
    version
        .value()
        .checked_add(1)
        .ok_or(IamError::Conflict)
        .and_then(|next| Ok(PolicyVersion::new(next)?))
}

#[async_trait::async_trait]
impl CommandHandler<ResyncPolicyCommand> for ResyncPolicyCommandHandler {
    async fn handle(&self, command: ResyncPolicyCommand) -> Result<(), IamError> {
        self.resync(command).await
    }
}

#[cfg(test)]
mod tests;
