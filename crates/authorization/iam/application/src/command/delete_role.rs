//! Deletes a custom role and revokes every assignment of it (FR-23).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, EventEnvelope, IamChange, IamChangeParts, IamUnitOfWork,
    IdempotencyRequest, RevocationCause, Role, RoleId, RoleName, RoleRepository, RoleStamp,
    RoleStatement, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, UserRole,
    UserRoleId, UserRolePageQuery, UserRoleParts, UserRoleRepository, UserRoleStamp,
    UserRoleStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of a deleted role.
const AUDIT_ACTION: &str = "role.delete";

/// The audit action of an assignment that the deletion of its role revoked.
const REVOKE_AUDIT_ACTION: &str = "user_role.revoke";

/// The number of assignments read per page.
const PAGE_LIMIT: u32 = 100;

/// The largest number of assignments that one deletion revokes in one transaction.
///
/// It is the default of `BULK_CHUNK_ENTITIES` (FR-84); a role with more assignments is refused as
/// a conflict until the bulk operation of Story 13.8 splits the deletion.
pub const MAX_REVOKED_ASSIGNMENTS: usize = 1_000;

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
}

/// The write of one revoked assignment: its statement, its events and its audit record.
struct Revocation {
    statement: ChangeStatement,
    events: Vec<EventEnvelope>,
    audit: SecurityAuditEvent,
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
        }
    }

    async fn delete(&self, command: DeleteRoleCommand) -> Result<(), IamError> {
        let role = self
            .roles
            .find_by_id(command.role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let assignments = self.assignments_of(command.role_id).await?;
        let change = self.change_of(role, assignments, command)?;
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// Every assignment of the role that is not revoked, expired ones included.
    ///
    /// # Errors
    ///
    /// [`IamError::Conflict`] when the role has more than [`MAX_REVOKED_ASSIGNMENTS`] of them.
    async fn assignments_of(&self, role_id: RoleId) -> Result<Vec<UserRole>, IamError> {
        let now = self.clock.now();
        let mut found = Vec::new();
        let mut after: Option<UserRoleId> = None;
        loop {
            let page = self
                .user_roles
                .find_page(&page_query(role_id, after, now))
                .await?;
            let last = page.last().map(|user_role| user_role.parts().id);
            let full = u32::try_from(page.len()) == Ok(PAGE_LIMIT);
            found.extend(page);
            if found.len() > MAX_REVOKED_ASSIGNMENTS {
                return Err(IamError::Conflict);
            }
            match last {
                Some(id) if full => after = Some(id),
                _ => return Ok(found),
            }
        }
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
        let summaries = (
            format!(
                "kind={} version={}",
                before.kind.as_str(),
                before.version.value()
            ),
            format!(
                "deleted version={} revoked={revoked}",
                role.parts().version.value()
            ),
        );
        let audit = self.audit(before.id, summaries, &stamp, idempotency.as_ref())?;
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
            .map(|assignment| self.revocation(assignment, role_name.clone(), role_stamp))
            .collect()
    }

    /// The revocation of one assignment, at the version it was read at.
    fn revocation(
        &self,
        mut user_role: UserRole,
        role_name: RoleName,
        role_stamp: &RoleStamp,
    ) -> Result<Revocation, IamError> {
        let before = user_role.parts().clone();
        let stamp = UserRoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: role_stamp.actor.clone(),
            occurred_at: role_stamp.occurred_at,
        };
        user_role.revoke(
            Some(before.version),
            role_name,
            RevocationCause::RoleDeleted,
            stamp.clone(),
        )?;
        Ok(Revocation {
            events: user_role.pull_envelopes()?,
            audit: self.revoke_audit(&before, user_role.parts(), &stamp)?,
            statement: ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::update(
                &user_role,
                before.version,
            ))),
        })
    }

    /// The committed audit record of the deletion of the role `id`, with the summaries of the role
    /// before it and after it.
    fn audit(
        &self,
        id: RoleId,
        summaries: (String, String),
        stamp: &RoleStamp,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let (held, ended) = summaries;
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("role", &id.to_string())?,
            scope: None,
            before: Some(AuditSummary::new(&held)?),
            after: Some(AuditSummary::new(&ended)?),
            idempotency_key: idempotency.map(|request| request.key.clone()),
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }

    /// The committed audit record of one assignment that the deletion revoked: the assignment
    /// before it, and the version it ended at.
    fn revoke_audit(
        &self,
        before: &UserRoleParts,
        after: &UserRoleParts,
        stamp: &UserRoleStamp,
    ) -> Result<SecurityAuditEvent, IamError> {
        let held = format!(
            "subject={} role={} scope={} version={}",
            before.subject,
            before.role_id,
            before.scope,
            before.version.value()
        );
        let ended = format!(
            "revoked version={} cause={}",
            after.version.value(),
            RevocationCause::RoleDeleted.as_str()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(REVOKE_AUDIT_ACTION)?,
            target: AuditTarget::new("user_role", &after.id.to_string())?,
            scope: Some(after.scope),
            before: Some(AuditSummary::new(&held)?),
            after: Some(AuditSummary::new(&ended)?),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The page of assignments of `role_id` after the cursor, expired ones included.
const fn page_query(
    role_id: RoleId,
    after: Option<UserRoleId>,
    now: SystemTime,
) -> UserRolePageQuery {
    UserRolePageQuery {
        limit: PAGE_LIMIT,
        after,
        subject_kind: None,
        subject_id: None,
        role_id: Some(role_id),
        project_id: None,
        include_expired: true,
        now,
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
