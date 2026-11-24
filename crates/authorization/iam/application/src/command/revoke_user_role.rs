//! Revokes an assignment (FR-29).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    RevocationCause, RoleName, RoleRepository, SecurityAuditEvent, SecurityAuditEventId,
    SecurityAuditEventParts, UserRole, UserRoleId, UserRoleParts, UserRoleRepository,
    UserRoleStamp, UserRoleStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::administrator_safeguard::AdministratorSafeguard;
use crate::error::IamError;

/// The audit action of a revoked assignment.
const AUDIT_ACTION: &str = "user_role.revoke";

/// Revokes the assignment `user_role_id` as `actor`, when the stored assignment still holds the
/// version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct RevokeUserRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The assignment to revoke.
    pub user_role_id: UserRoleId,
    /// Who revokes the assignment.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for RevokeUserRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "RevokeUserRoleCommand";
}

/// The repositories that a revocation reads before it decides.
#[derive(Debug, Clone)]
pub struct RevokeUserRoleReads {
    /// The assignments.
    pub user_roles: Arc<dyn UserRoleRepository>,
    /// The roles.
    pub roles: Arc<dyn RoleRepository>,
}

/// Handles [`RevokeUserRoleCommand`].
///
/// It reads the assignment and its role, lets the aggregate check the version and record the
/// revocation, and commits the update, its `iam.user_role.revoked` event and its audit record
/// through the unit of work in one transaction. A revocation affects decisions, so the change takes
/// the next policy version. An assignment that is unknown or already revoked is not found, and so
/// is one whose role no longer exists. The last active global administrator assignment is refused
/// as [`IamError::LastAdministrator`] and the refusal is audited, before anything is committed.
#[derive(Debug)]
pub struct RevokeUserRoleCommandHandler {
    user_roles: Arc<dyn UserRoleRepository>,
    roles: Arc<dyn RoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    safeguard: Arc<AdministratorSafeguard>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl RevokeUserRoleCommandHandler {
    /// A handler over the repositories it reads, the unit of work, the safeguard of the last
    /// administrator, the clock and the identifier source.
    #[must_use]
    pub fn new(
        reads: RevokeUserRoleReads,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        safeguard: Arc<AdministratorSafeguard>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            user_roles: reads.user_roles,
            roles: reads.roles,
            unit_of_work,
            safeguard,
            clock,
            uuid_generator,
        }
    }

    async fn revoke(&self, command: RevokeUserRoleCommand) -> Result<(), IamError> {
        let user_role = self
            .user_roles
            .find_by_id(command.user_role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let role = self
            .roles
            .find_by_id(user_role.parts().role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let before = user_role.parts().clone();
        let actor = command.actor.clone();
        let change = self.change_of(user_role, role.parts().name.clone(), command)?;
        let _admission = self.safeguard.admit_revocation(&before, &actor).await?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that revokes the assignment: the update, the event and the audit record.
    fn change_of(
        &self,
        mut user_role: UserRole,
        role_name: RoleName,
        command: RevokeUserRoleCommand,
    ) -> Result<IamChange, IamError> {
        let RevokeUserRoleCommand {
            change_id,
            actor,
            expected,
            idempotency,
            ..
        } = command;
        let before = user_role.parts().clone();
        let stamp = UserRoleStamp {
            event_id: self.uuid_generator.generate(),
            actor,
            occurred_at: self.clock.now(),
        };
        user_role.revoke(
            Some(expected),
            role_name,
            RevocationCause::Revoked,
            stamp.clone(),
        )?;
        let events = user_role.pull_envelopes()?;
        let audit = self.audit(&before, user_role.parts(), &stamp, idempotency.as_ref())?;
        let statement = UserRoleStatement::update(&user_role, expected);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::SaveUserRole(Box::new(statement))],
            events,
            audit,
            entity_version: user_role.parts().version,
            idempotency,
        })?)
    }

    /// The committed audit record of the revocation: the assignment before it, and the version it
    /// ended at.
    fn audit(
        &self,
        before: &UserRoleParts,
        after: &UserRoleParts,
        stamp: &UserRoleStamp,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let held = format!(
            "subject={} role={} scope={} version={}",
            before.subject,
            before.role_id,
            before.scope,
            before.version.value()
        );
        let ended = format!("revoked version={}", after.version.value());
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("user_role", &after.id.to_string())?,
            scope: Some(after.scope),
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
}

#[async_trait::async_trait]
impl CommandHandler<RevokeUserRoleCommand> for RevokeUserRoleCommandHandler {
    async fn handle(&self, command: RevokeUserRoleCommand) -> Result<(), IamError> {
        self.revoke(command).await
    }
}

#[cfg(test)]
mod tests;
