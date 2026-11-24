//! Deletes a custom role and revokes every assignment of it (FR-23).

use std::sync::Arc;

use iam_domain::{
    ActorRef, BulkChunker, BulkKind, BulkOperation, BulkOperationId, BulkOperationRepository,
    BulkRoleTargetStore, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, IamChange,
    IamChangeParts, IamUnitOfWork, IdempotencyRequest, Role, RoleId, RoleName, RoleRepository,
    RoleStamp, RoleStatement, UserRole, UserRoleId, UserRoleRepository,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::role_deletion::{self, PAGE_LIMIT, Revocation, page_query};
use crate::error::IamError;

/// The largest number of assignments that one deletion revokes in one transaction when no bulk
/// path is configured.
///
/// It is the default of `BULK_CHUNK_ENTITIES` (FR-84); a handler without a bulk path refuses a
/// role with more assignments as a conflict.
pub const MAX_REVOKED_ASSIGNMENTS: usize = 1_000;

/// The bulk path of a role deletion: a role whose deletion changes more than
/// `BULK_CHUNK_ENTITIES` entities is recorded as a pending bulk operation that the
/// `BulkOperationRunner` commits in chunks (FR-84).
#[derive(Debug, Clone)]
pub struct BulkDeletionPath {
    /// Where the pending operation is recorded.
    pub operations: Arc<dyn BulkOperationRepository>,
    /// Where the role of the operation is remembered.
    pub targets: Arc<dyn BulkRoleTargetStore>,
    /// The chunk size: `BULK_CHUNK_ENTITIES`.
    pub chunker: BulkChunker,
}

/// The assignments of a role that a deletion revokes.
enum Assignments {
    /// All of them, few enough for one change.
    Within(Vec<UserRole>),
    /// More than one change may revoke; the count of all of them.
    Beyond(usize),
}

/// Deletes the custom role `role_id` as `actor`, when the stored role still holds the version
/// `expected`, and revokes every assignment of it.
///
/// The caller chooses the identifier of the change, so that it can read the receipt, which holds
/// the number of revoked assignments, after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct DeleteRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The role to delete.
    pub role_id: RoleId,
    /// Who deletes the role.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for DeleteRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "DeleteRoleCommand";
}

/// Handles [`DeleteRoleCommand`].
///
/// It reads the role and every assignment of it that is not revoked, expired ones included, lets
/// the aggregates check the kind and the version and record `iam.role.deleted` and one
/// `iam.user_role.revoked` per assignment, and commits the deletion, the revocations, the events
/// and the audit records through the unit of work in one transaction. The change takes the next
/// policy version, because former holders lose access.
#[derive(Debug)]
pub struct DeleteRoleCommandHandler {
    roles: Arc<dyn RoleRepository>,
    user_roles: Arc<dyn UserRoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
    bulk: Option<BulkDeletionPath>,
}

impl DeleteRoleCommandHandler {
    /// A handler over the role and assignment repositories, the unit of work, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        roles: Arc<dyn RoleRepository>,
        user_roles: Arc<dyn UserRoleRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            roles,
            user_roles,
            unit_of_work,
            clock,
            uuid_generator,
            bulk: None,
        }
    }

    /// The same handler with a bulk path: a role with more assignments than one change may revoke
    /// is recorded as a bulk operation instead of being refused.
    #[must_use]
    pub fn with_bulk(mut self, bulk: BulkDeletionPath) -> Self {
        self.bulk = Some(bulk);
        self
    }

    async fn delete(&self, command: DeleteRoleCommand) -> Result<(), IamError> {
        let role = self
            .roles
            .find_by_id(command.role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        match self.assignments_of(command.role_id).await? {
            Assignments::Within(assignments) => {
                let change = self.change_of(role, assignments, command)?;
                self.unit_of_work
                    .commit(change, iam_domain::WriteMode::Published)
                    .await?;
                Ok(())
            }
            Assignments::Beyond(count) => self.record_bulk(&role, count, &command).await,
        }
    }

    /// The assignments of the role that are not revoked, expired ones included: all of them when
    /// one change may revoke them, otherwise their count.
    ///
    /// # Errors
    ///
    /// [`IamError::Conflict`] when the role has more assignments than one change may revoke and
    /// the handler has no bulk path.
    async fn assignments_of(&self, role_id: RoleId) -> Result<Assignments, IamError> {
        let now = self.clock.now();
        let limit = self.bulk.as_ref().map_or(MAX_REVOKED_ASSIGNMENTS, |bulk| {
            bulk.chunker.chunk_entities().saturating_sub(1)
        });
        let mut found = Vec::new();
        let mut counted = 0_usize;
        let mut after: Option<UserRoleId> = None;
        loop {
            let page = self
                .user_roles
                .find_page(&page_query(role_id, after, now))
                .await?;
            let last = page.last().map(|user_role| user_role.parts().id);
            let full = u32::try_from(page.len()) == Ok(PAGE_LIMIT);
            counted = counted.saturating_add(page.len());
            if counted <= limit {
                found.extend(page);
            } else if self.bulk.is_none() {
                return Err(IamError::Conflict);
            }
            match last {
                Some(id) if full => after = Some(id),
                _ if counted <= limit => return Ok(Assignments::Within(found)),
                _ => return Ok(Assignments::Beyond(counted)),
            }
        }
    }

    /// Records the deletion as a pending bulk operation over every assignment and the role itself.
    /// The deletion is checked as the single change would be (kind and version), so a refusal is
    /// the same, and the operation is named after the change.
    async fn record_bulk(
        &self,
        role: &Role,
        assignments: usize,
        command: &DeleteRoleCommand,
    ) -> Result<(), IamError> {
        let bulk = self.bulk.as_ref().ok_or(IamError::Conflict)?;
        let now = self.clock.now();
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: command.actor.clone(),
            occurred_at: now,
        };
        Role::restore(role.parts().clone()).delete(Some(command.expected), 0, stamp)?;
        let id = BulkOperationId::from_uuid(command.change_id.as_uuid());
        let total = u64::try_from(assignments)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let operation = BulkOperation::pending(
            id,
            BulkKind::RoleDeletion,
            total,
            command.actor.clone(),
            now,
        )
        .map_err(|_invalid| IamError::Conflict)?;
        bulk.targets.insert(id, command.role_id).await?;
        bulk.operations.insert(&operation).await?;
        Ok(())
    }

    /// The change that deletes the role: the deletion, the revocations, the events and the audit
    /// records.
    fn change_of(
        &self,
        mut role: Role,
        assignments: Vec<UserRole>,
        command: DeleteRoleCommand,
    ) -> Result<IamChange, IamError> {
        let DeleteRoleCommand {
            change_id,
            actor,
            expected,
            idempotency,
            ..
        } = command;
        let before = role.parts().clone();
        // `assignments_of` refuses more than `MAX_REVOKED_ASSIGNMENTS`, so the count fits.
        let revoked = u32::try_from(assignments.len()).unwrap_or(u32::MAX);
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: self.clock.now(),
        };
        role.delete(Some(expected), revoked, stamp.clone())?;
        let mut events = role.pull_envelopes()?;
        let summaries = role_deletion::summaries(&before, role.parts(), revoked);
        let key = idempotency.as_ref().map(|request| &request.key);
        let ids = self.uuid_generator.as_ref();
        let audit = role_deletion::role_audit(ids, before.id, summaries, &stamp, key)?;
        let statement = RoleStatement::update(&role, expected, actor);
        let mut statements = vec![ChangeStatement::SaveRole(Box::new(statement))];
        let mut related = Vec::new();
        for revocation in self.revocations(assignments, &before.name, &stamp)? {
            statements.push(revocation.statement);
            events.extend(revocation.events);
            related.push(revocation.audit);
        }
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements,
            events,
            audit,
            entity_version: role.parts().version,
            idempotency,
        })?;
        Ok(change
            .with_revoked_assignments(revoked)
            .with_related_audits(related)?)
    }

    /// The revocation of every assignment, in the order they were read, each with its own event
    /// identifier.
    fn revocations(
        &self,
        assignments: Vec<UserRole>,
        role_name: &RoleName,
        role_stamp: &RoleStamp,
    ) -> Result<Vec<Revocation>, IamError> {
        assignments
            .into_iter()
            .map(|assignment| {
                role_deletion::revocation(
                    self.uuid_generator.as_ref(),
                    assignment,
                    role_name.clone(),
                    role_stamp,
                )
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl CommandHandler<DeleteRoleCommand> for DeleteRoleCommandHandler {
    async fn handle(&self, command: DeleteRoleCommand) -> Result<(), IamError> {
        self.delete(command).await
    }
}

#[cfg(test)]
mod tests;
