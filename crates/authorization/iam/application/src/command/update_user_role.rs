//! Sets, extends, shortens or clears the expiry of an assignment (FR-28).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, UserRole, UserRoleId,
    UserRoleParts, UserRoleRepository, UserRoleStamp, UserRoleStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::administrator_safeguard::AdministratorSafeguard;
use crate::error::IamError;

/// The audit action of an updated assignment.
const AUDIT_ACTION: &str = "user_role.update";

/// Changes the expiry of the assignment `user_role_id` to `expires_at` as `actor`, when the stored
/// assignment still holds the version `expected`; `None` clears the expiry.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the
/// assignment after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct UpdateUserRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The assignment to change.
    pub user_role_id: UserRoleId,
    /// Who changes the assignment.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The new expiry, which must lie in the future; `None` for an assignment that never expires.
    pub expires_at: Option<SystemTime>,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for UpdateUserRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "UpdateUserRoleCommand";
}

/// Handles [`UpdateUserRoleCommand`].
///
/// It reads the assignment, lets the aggregate check the version and the expiry, and commits the
/// update, its `iam.user_role.updated` event and its audit record through the unit of work in one
/// transaction. An expiry changes what the assignment grants, so the change takes the next policy
/// version. An earlier expiry of the last active global administrator assignment is refused as
/// [`IamError::LastAdministrator`] and audited, before anything is committed.
#[derive(Debug)]
pub struct UpdateUserRoleCommandHandler {
    user_roles: Arc<dyn UserRoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    safeguard: Arc<AdministratorSafeguard>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl UpdateUserRoleCommandHandler {
    /// A handler over the assignment repository, the unit of work, the safeguard of the last
    /// administrator, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        user_roles: Arc<dyn UserRoleRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        safeguard: Arc<AdministratorSafeguard>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            user_roles,
            unit_of_work,
            safeguard,
            clock,
            uuid_generator,
        }
    }

    async fn update(&self, command: UpdateUserRoleCommand) -> Result<(), IamError> {
        let user_role = self
            .user_roles
            .find_by_id(command.user_role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let before = user_role.parts().clone();
        let (expires_at, actor) = (command.expires_at, command.actor.clone());
        let change = self.change_of(user_role, command)?;
        let _admission = self
            .safeguard
            .admit_expiry(&before, expires_at, &actor)
            .await?;
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// The change that updates the assignment: the update, the event and the audit record.
    fn change_of(
        &self,
        mut user_role: UserRole,
        command: UpdateUserRoleCommand,
    ) -> Result<IamChange, IamError> {
        let UpdateUserRoleCommand {
            change_id,
            actor,
            expected,
            expires_at,
            idempotency,
            ..
        } = command;
        let before = user_role.parts().clone();
        let stamp = UserRoleStamp {
            event_id: self.uuid_generator.generate(),
            actor,
            occurred_at: self.clock.now(),
        };
        user_role.change_expiry(Some(expected), expires_at, stamp.clone())?;
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

    /// The committed audit record of the update: the expiry and the version before and after.
    fn audit(
        &self,
        before: &UserRoleParts,
        after: &UserRoleParts,
        stamp: &UserRoleStamp,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("user_role", &after.id.to_string())?,
            scope: Some(after.scope),
            before: Some(AuditSummary::new(&summary_of(before))?),
            after: Some(AuditSummary::new(&summary_of(after))?),
            idempotency_key: idempotency.map(|request| request.key.clone()),
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The state of an assignment that its audit record keeps: the expiry and the version.
fn summary_of(user_role: &UserRoleParts) -> String {
    let expiry = user_role.expires_at.map_or_else(
        || "none".to_owned(),
        |expiry| humantime::format_rfc3339_micros(expiry.at()).to_string(),
    );
    format!("expiresAt={expiry} version={}", user_role.version.value())
}

#[async_trait::async_trait]
impl CommandHandler<UpdateUserRoleCommand> for UpdateUserRoleCommandHandler {
    async fn handle(&self, command: UpdateUserRoleCommand) -> Result<(), IamError> {
        self.update(command).await
    }
}

#[cfg(test)]
mod tests;
