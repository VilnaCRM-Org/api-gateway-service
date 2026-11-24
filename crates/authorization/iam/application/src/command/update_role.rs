//! Renames a custom role or changes its description (FR-20, FR-22).

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    InvalidRole, Role, RoleDescription, RoleDescriptionChange, RoleId, RoleName, RoleParts,
    RolePatch, RoleRepository, RoleStamp, RoleStatement, SecurityAuditEvent, SecurityAuditEventId,
    SecurityAuditEventParts,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};
use std::sync::Arc;

use crate::error::IamError;

/// The audit action of an updated role.
const AUDIT_ACTION: &str = "role.update";

/// What an update does with the description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DescriptionUpdate {
    /// Keeps the stored description.
    #[default]
    Keep,
    /// Removes the description.
    Remove,
    /// Replaces the description with the text.
    Set(String),
}

/// Changes the name and the description of the custom role `role_id` as `actor`, when the stored
/// role still holds the version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the role
/// after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct UpdateRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The role to change.
    pub role_id: RoleId,
    /// Who changes the role.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The new name, when it changes.
    pub name: Option<String>,
    /// What happens to the description.
    pub description: DescriptionUpdate,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for UpdateRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "UpdateRoleCommand";
}

/// Handles [`UpdateRoleCommand`].
///
/// It reads the role, applies the validated patch (the aggregate checks the kind and the
/// version) and commits the update, its `iam.role.updated` event and its audit record through the
/// unit of work in one transaction. A role name or description does not affect any decision, so
/// the change takes no policy version.
#[derive(Debug)]
pub struct UpdateRoleCommandHandler {
    roles: Arc<dyn RoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl UpdateRoleCommandHandler {
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

    async fn update(&self, command: UpdateRoleCommand) -> Result<(), IamError> {
        let role = self
            .roles
            .find_by_id(command.role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(role, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that updates the role: the update, the event and the audit record.
    fn change_of(&self, mut role: Role, command: UpdateRoleCommand) -> Result<IamChange, IamError> {
        let UpdateRoleCommand {
            change_id,
            actor,
            expected,
            name,
            description,
            idempotency,
            ..
        } = command;
        let now = self.clock.now();
        let patch = patch_of(name, description)?;
        let before = role.parts().clone();
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        role.update(Some(expected), patch, stamp.clone())?;
        let events = role.pull_envelopes()?;
        let audit = self.audit(&before, role.parts(), &stamp, idempotency.as_ref())?;
        let statement = RoleStatement::update(&role, expected, actor);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Unaffected,
            statements: vec![ChangeStatement::SaveRole(Box::new(statement))],
            events,
            audit,
            entity_version: role.parts().version,
            idempotency,
        })?)
    }

    /// The committed audit record of the update: the versions before and after, never the text.
    fn audit(
        &self,
        before: &RoleParts,
        after: &RoleParts,
        stamp: &RoleStamp,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("role", &after.id.to_string())?,
            scope: None,
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

/// The state of a role that its audit record keeps: the kind and the version.
fn summary_of(role: &RoleParts) -> String {
    format!(
        "kind={} version={}",
        role.kind.as_str(),
        role.version.value()
    )
}

/// The validated patch of the name and the description.
///
/// # Errors
///
/// [`IamError::Invalid`] with every violation, in the order name then description.
fn patch_of(name: Option<String>, description: DescriptionUpdate) -> Result<RolePatch, IamError> {
    let name = name.map(RoleName::new).transpose();
    let description = match description {
        DescriptionUpdate::Keep => Ok(RoleDescriptionChange::Keep),
        DescriptionUpdate::Remove => Ok(RoleDescriptionChange::Remove),
        DescriptionUpdate::Set(text) => RoleDescription::new(text).map(RoleDescriptionChange::Set),
    };
    match (name, description) {
        (Ok(name), Ok(description)) => Ok(RolePatch { name, description }),
        (name, description) => {
            let violations: Vec<InvalidRole> =
                name.err().into_iter().chain(description.err()).collect();
            Err(IamError::from(violations))
        }
    }
}

#[async_trait::async_trait]
impl CommandHandler<UpdateRoleCommand> for UpdateRoleCommandHandler {
    async fn handle(&self, command: UpdateRoleCommand) -> Result<(), IamError> {
        self.update(command).await
    }
}

#[cfg(test)]
mod tests;
