//! Creates the first IAM administrator: the system role `iam-platform-admin` with its keys and its
//! global assignment to one subject (FR-5).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AssignmentScope, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork,
    LastAdministratorGuard, PermissionGrant, PermissionGrantSet, PlatformAdministrator,
    PrivilegedGrants, Role, RoleFields, RoleId, RolePageQuery, RoleParts, RoleRepository,
    RoleStamp, RoleStatement, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    SubjectRef, SystemComponent, UserRole, UserRoleAssignment, UserRoleId, UserRolePageQuery,
    UserRoleRepository, UserRoleStamp, UserRoleStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of the bootstrap.
const AUDIT_ACTION: &str = "iam.bootstrap";

/// The description of the system role.
const ROLE_DESCRIPTION: &str = "Administers IAM and holds every reserved key.";

/// The number of roles or assignments that one read asks for.
const PAGE: u32 = 100;

/// The command that gives `subject` the role `iam-platform-admin` at global scope as
/// `system:bootstrap`, creating the role first when it does not exist.
///
/// The caller chooses the identifiers of the change, of the role (used when the role does not
/// exist yet) and of the assignment; the command returns no data.
#[derive(Debug, Clone)]
pub struct BootstrapIamCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the role when it is created.
    pub role_id: RoleId,
    /// The identifier of the new assignment.
    pub user_role_id: UserRoleId,
    /// The first administrator: a user or a service principal.
    pub subject: SubjectRef,
}

impl Command for BootstrapIamCommand {
    type Error = IamError;
    const NAME: &'static str = "BootstrapIamCommand";
}

/// Handles [`BootstrapIamCommand`].
///
/// It refuses with [`IamError::Conflict`] when an assignment of the administrator role is active
/// at global scope already. Otherwise it commits, in one transaction, the insert of the role with
/// its grants (or the replacement of the grants of a role that exists with others), the insert of
/// the assignment, their events, including the alert of the privileged assignment, and one
/// audit record with the actor `system:bootstrap`. The caller serializes concurrent runs.
#[derive(Debug)]
pub struct BootstrapIamCommandHandler {
    roles: Arc<dyn RoleRepository>,
    user_roles: Arc<dyn UserRoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

/// The actor of every change of the bootstrap.
const fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Bootstrap)
}

/// The grants of the administrator role.
fn administrator_grants() -> Result<PermissionGrantSet, IamError> {
    grants_of(&PlatformAdministrator::GRANTS)
}

/// The grant set of `texts`; a text that does not parse is an internal error, because the texts
/// are the constants of the administrator role.
fn grants_of(texts: &[&str]) -> Result<PermissionGrantSet, IamError> {
    let grants = texts
        .iter()
        .map(|text| PermissionGrant::parse(text))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| IamError::Internal(Box::new(error)))?;
    Ok(PermissionGrantSet::new(grants)?)
}

impl BootstrapIamCommandHandler {
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

    async fn bootstrap(&self, command: &BootstrapIamCommand) -> Result<(), IamError> {
        let existing = self.administrator_role().await?;
        if let Some(role) = &existing
            && self
                .has_active_administrator(role.parts().id, command.user_role_id)
                .await?
        {
            return Err(IamError::Conflict);
        }
        let change = self.change_of(existing, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The system role `iam-platform-admin`, when it exists.
    async fn administrator_role(&self) -> Result<Option<Role>, IamError> {
        let query = RolePageQuery {
            limit: PAGE,
            after: None,
            name_prefix: Some(PlatformAdministrator::ROLE_NAME.to_owned()),
            kind: Some(iam_domain::RoleKind::System),
        };
        let page = self.roles.find_page(&query).await?;
        Ok(page
            .into_iter()
            .find(|role| PlatformAdministrator::is_role(role.parts())))
    }

    /// Whether an assignment of the role other than `fresh` is active at global scope now.
    async fn has_active_administrator(
        &self,
        role_id: RoleId,
        fresh: UserRoleId,
    ) -> Result<bool, IamError> {
        let now = self.clock.now();
        let mut after = None;
        loop {
            let query = UserRolePageQuery {
                limit: PAGE,
                after,
                subject_kind: None,
                subject_id: None,
                role_id: Some(role_id),
                project_id: None,
                include_expired: false,
                now,
            };
            let page = self.user_roles.find_page(&query).await?;
            if page.iter().any(|user_role| {
                LastAdministratorGuard::is_other_administrator(user_role.parts(), fresh, now)
            }) {
                return Ok(true);
            }
            let full = u32::try_from(page.len()).is_ok_and(|length| length >= PAGE);
            match page.last() {
                Some(last) if full => after = Some(last.parts().id),
                _ => return Ok(false),
            }
        }
    }

    fn role_stamp(&self, now: SystemTime) -> RoleStamp {
        RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor(),
            occurred_at: now,
        }
    }

    /// The role as the bootstrap leaves it, with the statement that writes it, when it changes:
    /// a new system role with every grant, a role that exists with other grants replaced, or a
    /// role that exists and is complete, which needs no write.
    fn role_of(
        &self,
        existing: Option<Role>,
        role_id: RoleId,
        now: SystemTime,
    ) -> Result<(Role, Option<RoleStatement>), IamError> {
        let grants = administrator_grants()?;
        let Some(mut role) = existing else {
            let name = PlatformAdministrator::ROLE_NAME.to_owned();
            let fields = RoleFields::new(name, Some(ROLE_DESCRIPTION.to_owned()))?;
            let (created, updated) = (self.role_stamp(now), self.role_stamp(now));
            let role = Role::create_system(role_id, fields, grants, created, updated)?;
            let statement = RoleStatement::insert(&role, actor());
            return Ok((role, Some(statement)));
        };
        if role.parts().grants == grants {
            return Ok((role, None));
        }
        let expected = role.parts().version;
        role.replace_permissions(Some(expected), grants, self.role_stamp(now))?;
        let statement = RoleStatement::update(&role, expected, actor());
        Ok((role, Some(statement)))
    }

    /// The change that bootstraps: the role write, the assignment insert, the events and the
    /// audit record.
    fn change_of(
        &self,
        existing: Option<Role>,
        command: &BootstrapIamCommand,
    ) -> Result<IamChange, IamError> {
        let now = self.clock.now();
        let (mut role, role_statement) = self.role_of(existing, command.role_id, now)?;
        let mut events = role.pull_envelopes()?;
        let mut user_role = self.assignment_of(role.parts(), command, now)?;
        events.extend(user_role.pull_envelopes()?);
        let audit = self.audit(user_role.parts(), now)?;
        let statements = role_statement
            .map(|statement| ChangeStatement::SaveRole(Box::new(statement)))
            .into_iter()
            .chain([ChangeStatement::SaveUserRole(Box::new(
                UserRoleStatement::insert(&user_role),
            ))])
            .collect();
        Ok(IamChange::new(IamChangeParts {
            change_id: command.change_id,
            effect: DecisionEffect::Affected,
            statements,
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?)
    }

    /// The global assignment of the role to the subject, with the alert of its privileged grants.
    fn assignment_of(
        &self,
        role: &RoleParts,
        command: &BootstrapIamCommand,
        now: SystemTime,
    ) -> Result<UserRole, IamError> {
        let assignment = UserRoleAssignment {
            id: command.user_role_id,
            subject: command.subject.clone(),
            role_id: role.id,
            role_name: role.name.clone(),
            scope: AssignmentScope::Global,
            expires_at: None,
            privileged: Some(PrivilegedGrants {
                event_id: self.uuid_generator.generate(),
                keys: role.grants.iter().cloned().collect(),
            }),
        };
        let stamp = UserRoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor(),
            occurred_at: now,
        };
        Ok(UserRole::assign(assignment, stamp)?)
    }

    /// The committed audit record of the bootstrap.
    fn audit(
        &self,
        user_role: &iam_domain::UserRoleParts,
        now: SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let after = format!(
            "subject={} role={} scope={} version=1",
            user_role.subject, user_role.role_id, user_role.scope
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: actor(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("user_role", &user_role.id.to_string())?,
            scope: Some(user_role.scope),
            before: None,
            after: Some(AuditSummary::new(&after)?),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<BootstrapIamCommand> for BootstrapIamCommandHandler {
    async fn handle(&self, command: BootstrapIamCommand) -> Result<(), IamError> {
        self.bootstrap(&command).await
    }
}

#[cfg(test)]
mod tests;
