//! The chunk committer of a role-deletion bulk operation (FR-1, FR-84).
//!
//! A role with more assignments than `BULK_CHUNK_ENTITIES` is deleted in versions of at most that
//! many revocations, and the version that follows the last revocations deletes the role itself.
//! Every revocation is revoke-type, so no intermediate version grants anything the previous state
//! did not. Each chunk is one change: the revocations (or the deletion), their events and audit
//! records, and the progress of the operation, committed together under a guard on the policy
//! version the chunk was decided against.

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, BulkChunkCommitter,
    BulkChunker, BulkOperation, BulkProgressStatement, BulkRoleTargetStore, BulkStamp, ChangeId,
    ChangeStatement, ChunkCommitError, CommittedChunk, DecisionEffect, EntityVersion,
    EventEnvelope, IamChange, IamChangeParts, IamUnitOfWork, PolicyEpochRepository, PolicyVersion,
    Role, RoleRepository, RoleStamp, RoleStatement, SecurityAuditEvent, SecurityAuditEventId,
    SecurityAuditEventParts, UserRole, UserRoleRepository, WriteMode,
};
use shared_domain::UuidGenerator;

use crate::command::role_deletion::{self, PAGE_LIMIT, page_query};

/// The audit action of one committed chunk of a bulk operation.
const CHUNK_AUDIT_ACTION: &str = "bulk_operation.chunk";

/// The ports of the committer.
#[derive(Debug, Clone)]
pub struct RoleDeletionPorts {
    /// Reads the role that is deleted.
    pub roles: Arc<dyn RoleRepository>,
    /// Reads the assignments that remain.
    pub user_roles: Arc<dyn UserRoleRepository>,
    /// The role that each operation deletes.
    pub targets: Arc<dyn BulkRoleTargetStore>,
    /// The policy version a chunk is decided against.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
    /// Commits a chunk as one change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The identifiers of changes, events and audit records.
    pub ids: Arc<dyn UuidGenerator>,
}

/// What the next chunk of a role deletion does.
enum Step {
    /// Revoke these assignments.
    Revoke(Vec<UserRole>),
    /// Delete the role: no assignment is left.
    Delete,
}

/// The change of one chunk and the records it applies.
struct Chunk {
    change: IamChange,
    records: u64,
}

/// Commits the chunks of a bulk operation of kind `role_deletion`.
#[derive(Debug)]
pub struct RoleDeletionChunkCommitter {
    ports: RoleDeletionPorts,
    chunker: BulkChunker,
}

impl RoleDeletionChunkCommitter {
    /// A committer over its ports that revokes at most `chunker.chunk_entities()` assignments per
    /// version.
    #[must_use]
    pub const fn new(ports: RoleDeletionPorts, chunker: BulkChunker) -> Self {
        Self { ports, chunker }
    }

    async fn commit(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        let role = self.role_of(operation).await?;
        let locked = self
            .ports
            .policy_epochs
            .current()
            .await
            .map_err(unavailable)?
            .version();
        let version = next_version(locked)?;
        let step = self.step_of(operation, &role, stamp.occurred_at).await?;
        let chunk = self.chunk_of(operation, role, step, (stamp, version))?;
        let records = chunk.records;
        self.ports
            .unit_of_work
            .commit(
                chunk.change.expecting_policy_version(locked),
                WriteMode::Published,
            )
            .await
            .map_err(unavailable)?;
        Ok(CommittedChunk { records, version })
    }

    /// The role that the operation deletes.
    async fn role_of(&self, operation: &BulkOperation) -> Result<Role, ChunkCommitError> {
        let id = self
            .ports
            .targets
            .find(operation.parts().id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| permanent("the role of the deletion is not recorded"))?;
        self.ports
            .roles
            .find_by_id(id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| permanent("the role no longer exists"))
    }

    /// The next step: the next assignments to revoke, or the deletion of the role when none is
    /// left. The last record of the operation is the role itself, so a role that gained
    /// assignments after the operation was recorded fails it.
    async fn step_of(
        &self,
        operation: &BulkOperation,
        role: &Role,
        now: SystemTime,
    ) -> Result<Step, ChunkCommitError> {
        let room = usize::try_from(operation.remaining_records().saturating_sub(1))
            .unwrap_or(usize::MAX)
            .min(self.chunker.chunk_entities());
        let found = self.assignments(role, room.max(1), now).await?;
        match (found.is_empty(), room) {
            (true, _) => Ok(Step::Delete),
            (false, 0) => Err(permanent(
                "the role gained assignments after the bulk operation was recorded",
            )),
            (false, room) => Ok(Step::Revoke(found.into_iter().take(room).collect())),
        }
    }

    /// Up to `limit` assignments of the role that are not revoked, expired ones included.
    async fn assignments(
        &self,
        role: &Role,
        limit: usize,
        now: SystemTime,
    ) -> Result<Vec<UserRole>, ChunkCommitError> {
        let mut found: Vec<UserRole> = Vec::new();
        while found.len() < limit {
            let after = found.last().map(|user_role| user_role.parts().id);
            let page = self
                .ports
                .user_roles
                .find_page(&page_query(role.parts().id, after, now))
                .await
                .map_err(unavailable)?;
            let full = u32::try_from(page.len()) == Ok(PAGE_LIMIT);
            found.extend(page);
            if !full {
                break;
            }
        }
        Ok(found)
    }

    fn chunk_of(
        &self,
        operation: &BulkOperation,
        role: Role,
        step: Step,
        (stamp, version): (BulkStamp, PolicyVersion),
    ) -> Result<Chunk, ChunkCommitError> {
        let actor = operation.parts().requester.clone();
        let role_stamp = RoleStamp {
            event_id: self.ports.ids.generate(),
            actor: actor.clone(),
            occurred_at: stamp.occurred_at,
        };
        let Parts {
            statements,
            events,
            related,
            records,
            entity_version,
        } = match step {
            Step::Revoke(assignments) => self.revocations(assignments, &role, &role_stamp)?,
            Step::Delete => self.deletion(operation, role, &role_stamp)?,
        };
        let mut progress = BulkOperation::restore(operation.parts().clone()).map_err(permanent)?;
        progress
            .record_chunk(records, version, stamp)
            .map_err(permanent)?;
        let mut events = events;
        events.extend(progress.pull_envelopes().map_err(permanent)?);
        let mut statements = statements;
        statements.push(ChangeStatement::SaveBulkProgress(Box::new(
            BulkProgressStatement::after_chunk(&progress, operation.parts().applied_records),
        )));
        let audit = self.audit(operation, &progress, &actor, &role_stamp)?;
        let change = IamChange::new(IamChangeParts {
            change_id: ChangeId::from_uuid(self.ports.ids.generate()),
            effect: DecisionEffect::Affected,
            statements,
            events,
            audit,
            entity_version,
            idempotency: None,
        })
        .map_err(permanent)?
        .with_related_audits(related)
        .map_err(permanent)?;
        Ok(Chunk { change, records })
    }

    /// The statements, events and audit records of the revocation of `assignments`.
    fn revocations(
        &self,
        assignments: Vec<UserRole>,
        role: &Role,
        role_stamp: &RoleStamp,
    ) -> Result<Parts, ChunkCommitError> {
        let records = u64::try_from(assignments.len()).unwrap_or(u64::MAX);
        let mut statements = Vec::new();
        let mut events = Vec::new();
        let mut related = Vec::new();
        for assignment in assignments {
            let revocation = role_deletion::revocation(
                self.ports.ids.as_ref(),
                assignment,
                role.parts().name.clone(),
                role_stamp,
            )
            .map_err(permanent)?;
            statements.push(revocation.statement);
            events.extend(revocation.events);
            related.push(revocation.audit);
        }
        Ok(Parts {
            statements,
            events,
            related,
            records,
            entity_version: role.parts().version,
        })
    }

    /// The statement, event and audit record of the deletion of the role; it applies every record
    /// that remains, the revocations that other changes made in the meantime included.
    fn deletion(
        &self,
        operation: &BulkOperation,
        mut role: Role,
        role_stamp: &RoleStamp,
    ) -> Result<Parts, ChunkCommitError> {
        let before = role.parts().clone();
        let revoked =
            u32::try_from(operation.parts().total_records.saturating_sub(1)).unwrap_or(u32::MAX);
        role.delete(Some(before.version), revoked, role_stamp.clone())
            .map_err(permanent)?;
        let events = role.pull_envelopes().map_err(permanent)?;
        let summaries = role_deletion::summaries(&before, role.parts(), revoked);
        let audit = role_deletion::role_audit(
            self.ports.ids.as_ref(),
            before.id,
            summaries,
            role_stamp,
            None,
        )
        .map_err(permanent)?;
        let statement = RoleStatement::update(&role, before.version, role_stamp.actor.clone());
        Ok(Parts {
            statements: vec![ChangeStatement::SaveRole(Box::new(statement))],
            events,
            related: vec![audit],
            records: operation.remaining_records(),
            entity_version: role.parts().version,
        })
    }

    /// The audit record of the chunk: the progress before it and after it.
    fn audit(
        &self,
        operation: &BulkOperation,
        progress: &BulkOperation,
        actor: &ActorRef,
        stamp: &RoleStamp,
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

/// The statements, events, related audit records and applied records of one chunk, and the
/// version of the role after it.
struct Parts {
    statements: Vec<ChangeStatement>,
    events: Vec<EventEnvelope>,
    related: Vec<SecurityAuditEvent>,
    records: u64,
    entity_version: EntityVersion,
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
impl BulkChunkCommitter for RoleDeletionChunkCommitter {
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
