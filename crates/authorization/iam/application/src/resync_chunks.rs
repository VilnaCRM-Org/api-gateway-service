//! The chunk committer of a resync bulk operation (FR-1, FR-78, FR-84).
//!
//! The resync of [`ResyncPolicyCommandHandler`](crate::command::resync_policy::ResyncPolicyCommandHandler)
//! already moved the policy to a new log epoch. Each chunk publishes the unchanged state of the
//! next entities of the policy under that epoch, as a versioned transaction of its own: the
//! entities are the next page of the stable order of the inventory, so every version continues
//! above the version before it and the chunks together cover the whole policy. A chunk writes no
//! entity, so the digest of the policy stays and the shadow bootstrap of the topic rebuilds it.
//!
//! A chunk counts the records it was asked to apply even when the policy shrank since the
//! operation was recorded and the page is shorter, so the operation always completes.

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, BulkChunkCommitter,
    BulkChunker, BulkOperation, BulkProgressStatement, BulkStamp, ChangeId, ChangeStatement,
    ChunkCommitError, CommittedChunk, DecisionEffect, EntityVersion, IamChange, IamChangeParts,
    IamUnitOfWork, InventoryEntry, PolicyEpochRepository, PolicyStateInventory, PolicyVersion,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, WriteMode,
};
use shared_domain::UuidGenerator;

/// The audit action of one committed chunk of a bulk operation.
const CHUNK_AUDIT_ACTION: &str = "bulk_operation.chunk";

/// The ports of the committer.
#[derive(Debug, Clone)]
pub struct ResyncPorts {
    /// The policy version a chunk is decided against.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
    /// Lists the entities to publish.
    pub inventory: Arc<dyn PolicyStateInventory>,
    /// Commits a chunk as one change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The identifiers of changes and audit records.
    pub ids: Arc<dyn UuidGenerator>,
}

/// Commits the chunks of a bulk operation of kind `resync`.
#[derive(Debug)]
pub struct ResyncChunkCommitter {
    ports: ResyncPorts,
    chunker: BulkChunker,
}

impl ResyncChunkCommitter {
    /// A committer over its ports that publishes at most `chunker.chunk_entities()` entities per
    /// version.
    #[must_use]
    pub const fn new(ports: ResyncPorts, chunker: BulkChunker) -> Self {
        Self { ports, chunker }
    }

    async fn commit(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        let locked = self
            .ports
            .policy_epochs
            .current()
            .await
            .map_err(unavailable)?
            .version();
        let version = next_version(locked)?;
        let records = operation
            .remaining_records()
            .min(u64::try_from(self.chunker.chunk_entities()).unwrap_or(u64::MAX));
        let entries = self
            .ports
            .inventory
            .page(operation.parts().applied_records, records)
            .await
            .map_err(unavailable)?;
        let change = self.change_of(operation, entries, records, (stamp, version))?;
        self.ports
            .unit_of_work
            .commit(
                change.expecting_policy_version(locked),
                WriteMode::Published,
            )
            .await
            .map_err(unavailable)?;
        Ok(CommittedChunk { records, version })
    }

    /// The change of one chunk: the republication of `entries`, the progress of the operation and
    /// the audit record.
    fn change_of(
        &self,
        operation: &BulkOperation,
        entries: Vec<InventoryEntry>,
        records: u64,
        (stamp, version): (BulkStamp, PolicyVersion),
    ) -> Result<IamChange, ChunkCommitError> {
        let mut progress = BulkOperation::restore(operation.parts().clone()).map_err(permanent)?;
        progress
            .record_chunk(records, version, stamp)
            .map_err(permanent)?;
        let events = progress.pull_envelopes().map_err(permanent)?;
        let statements = vec![
            ChangeStatement::RepublishState(Box::new(InventoryEntry::republication(entries))),
            ChangeStatement::SaveBulkProgress(Box::new(BulkProgressStatement::after_chunk(
                &progress,
                operation.parts().applied_records,
            ))),
        ];
        let actor = &operation.parts().requester;
        let audit = self.audit(operation, &progress, actor, &stamp)?;
        IamChange::new(IamChangeParts {
            change_id: ChangeId::from_uuid(self.ports.ids.generate()),
            effect: DecisionEffect::Affected,
            statements,
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })
        .map_err(permanent)
    }

    /// The audit record of the chunk: the progress before it and after it.
    fn audit(
        &self,
        operation: &BulkOperation,
        progress: &BulkOperation,
        actor: &ActorRef,
        stamp: &BulkStamp,
    ) -> Result<SecurityAuditEvent, ChunkCommitError> {
        let before = operation.parts();
        let after = progress.parts();
        let held = format!(
            "applied={} total={}",
            before.applied_records, before.total_records
        );
        let ended = format!(
            "applied={} total={} status={}",
            after.applied_records,
            after.total_records,
            after.status.as_str()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.ports.ids.generate()),
            occurred_at: stamp.occurred_at,
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(CHUNK_AUDIT_ACTION).map_err(permanent)?,
            target: AuditTarget::new("bulk_operation", &before.id.to_string())
                .map_err(permanent)?,
            scope: None,
            before: Some(AuditSummary::new(&held).map_err(permanent)?),
            after: Some(AuditSummary::new(&ended).map_err(permanent)?),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        SecurityAuditEvent::record(parts).map_err(permanent)
    }
}

/// The policy version the chunk takes: the one after `locked`.
fn next_version(locked: PolicyVersion) -> Result<PolicyVersion, ChunkCommitError> {
    locked
        .value()
        .checked_add(1)
        .ok_or_else(|| permanent("the policy version cannot grow"))
        .and_then(|value| PolicyVersion::new(value).map_err(permanent))
}

/// A failure that retrying cannot fix.
fn permanent(reason: impl std::fmt::Display) -> ChunkCommitError {
    ChunkCommitError::Permanent(reason.to_string())
}

/// A failure that a later attempt may overcome.
fn unavailable(error: impl std::error::Error + Send + Sync + 'static) -> ChunkCommitError {
    ChunkCommitError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl BulkChunkCommitter for ResyncChunkCommitter {
    async fn commit_next_chunk(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        self.commit(operation, stamp).await
    }
}

#[cfg(test)]
mod tests;
