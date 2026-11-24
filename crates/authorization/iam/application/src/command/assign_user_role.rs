//! Assigns a role to a user or a service principal (FR-26).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AssignmentScope, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, GuardCheck, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, InvalidUserRole, PermissionGrant, PrivilegedGrants, RoleId,
    RoleParts, RoleRepository, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    SubjectRef, UserRole, UserRoleAssignment, UserRoleId, UserRoleParts, UserRoleStamp,
    UserRoleStatement,
};
use shared_application::http::Violation;
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of an assignment.
const AUDIT_ACTION: &str = "user_role.assign";

/// The command that assigns `role_id` to `subject` at `scope`, as `actor`.
///
/// The caller chooses the identifiers of the assignment and of the change, so that it can read the
/// receipt and the assignment after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct AssignUserRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the new assignment.
    pub user_role_id: UserRoleId,
    /// Who assigns the role.
    pub actor: ActorRef,
    /// Who receives the role.
    pub subject: SubjectRef,
    /// The role to assign; it must exist and not be deleted.
    pub role_id: RoleId,
    /// Where the role applies.
    pub scope: AssignmentScope,
    /// When the assignment expires; it must lie in the future.
    pub expires_at: Option<SystemTime>,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for AssignUserRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "AssignUserRoleCommand";
}

/// Handles [`AssignUserRoleCommand`].
///
/// It reads the role, builds the assignment and commits its insert, its `iam.user_role.assigned`
/// event (and `iam.privileged_role.assigned` when the role grants a wildcard or a reserved key) and
/// its audit record through the unit of work in one transaction. The change affects decisions, so
/// it takes the next policy version; a duplicate triple refuses it as a conflict.
#[derive(Debug)]
pub struct AssignUserRoleCommandHandler {
    roles: Arc<dyn RoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl AssignUserRoleCommandHandler {
    /// A handler over the role repository, the unit of work, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        roles: Arc<dyn RoleRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            roles,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn assign(&self, command: AssignUserRoleCommand) -> Result<(), IamError> {
        let role = self
            .roles
            .find_by_id(command.role_id)
            .await?
            .ok_or_else(unknown_role)?;
        let change = self.change_of(command, role.parts())?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that assigns the role: the insert, the events and the audit record.
    fn change_of(
        &self,
        command: AssignUserRoleCommand,
        role: &RoleParts,
    ) -> Result<IamChange, IamError> {
        let AssignUserRoleCommand {
            change_id,
            user_role_id,
            actor,
            subject,
            role_id,
            scope,
            expires_at,
            idempotency,
        } = command;
        let now = self.clock.now();
        let guard = GuardCheck::Assignment {
            subject: subject.clone(),
            role_id,
        };
        let assignment = UserRoleAssignment {
            id: user_role_id,
            subject,
            role_id,
            role_name: role.name.clone(),
            scope,
            expires_at,
            privileged: self.privileged(role),
        };
        let stamp = UserRoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        let mut user_role = UserRole::assign(assignment, stamp).map_err(invalid_expiry)?;
        let events = user_role.pull_envelopes()?;
        let audit = self.audit(user_role.parts(), &actor, idempotency.as_ref(), now)?;
        let statement = UserRoleStatement::insert(&user_role);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::SaveUserRole(Box::new(statement))],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?
        .with_guard(guard))
    }

    /// The wildcards and reserved keys of the role with the id of their alert, none when it holds
    /// no such grant.
    fn privileged(&self, role: &RoleParts) -> Option<PrivilegedGrants> {
        let keys: Vec<PermissionGrant> = role
            .grants
            .iter()
            .filter(|grant| grant.is_privileged())
            .cloned()
            .collect();
        (!keys.is_empty()).then(|| PrivilegedGrants {
            event_id: self.uuid_generator.generate(),
            keys,
        })
    }

    /// The committed audit record of the assignment.
    fn audit(
        &self,
        user_role: &UserRoleParts,
        actor: &ActorRef,
        idempotency: Option<&IdempotencyRequest>,
        now: SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let after = format!(
            "subject={} role={} scope={} version=1",
            user_role.subject, user_role.role_id, user_role.scope
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("user_role", &user_role.id.to_string())?,
            scope: Some(user_role.scope),
            before: None,
            after: Some(AuditSummary::new(&after)?),
            idempotency_key: idempotency.map(|request| request.key.clone()),
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The refusal of a role that does not exist or is deleted: a violation of `roleId`.
fn unknown_role() -> IamError {
    IamError::Invalid(vec![Violation {
        property_path: "roleId".to_owned(),
        message: "This role does not exist.".to_owned(),
        code: "exists".to_owned(),
    }])
}

/// The refusal of an expiry that is not in the future: a violation of `expiresAt`.
fn invalid_expiry(error: InvalidUserRole) -> IamError {
    IamError::Invalid(vec![Violation {
        property_path: error.property_path().to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }])
}

#[async_trait::async_trait]
impl CommandHandler<AssignUserRoleCommand> for AssignUserRoleCommandHandler {
    async fn handle(&self, command: AssignUserRoleCommand) -> Result<(), IamError> {
        self.assign(command).await
    }
}

#[cfg(test)]
mod tests;
