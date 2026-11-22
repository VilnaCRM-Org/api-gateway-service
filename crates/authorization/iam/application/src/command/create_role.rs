//! Creates a custom role (FR-20).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    Role, RoleFields, RoleId, RoleParts, RoleStamp, RoleStatement, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of a created role.
const AUDIT_ACTION: &str = "role.create";

/// The state of a created role that its audit record keeps: the kind and the first version.
const AUDIT_AFTER: &str = "kind=custom version=1";

/// Creates a role with the name and the optional description, as `actor`.
///
/// The caller chooses the identifiers of the role and of the change, so that it can read the
/// receipt and the role after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateRoleCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the new role.
    pub role_id: RoleId,
    /// Who creates the role.
    pub actor: ActorRef,
    /// The name, which must be unique without regard to case among the roles that are not deleted.
    pub name: String,
    /// The optional description.
    pub description: Option<String>,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateRoleCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateRoleCommand";
}

/// Handles [`CreateRoleCommand`].
///
/// It validates the fields, builds the role and commits its insert, its `iam.role.created` event
/// and its audit record through the unit of work in one transaction. A role does not affect any
/// decision until it has grants, so the change takes no policy version.
#[derive(Debug)]
pub struct CreateRoleCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl CreateRoleCommandHandler {
    /// A handler over the unit of work, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn create(&self, command: CreateRoleCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// The change that creates the role: the insert, the event and the audit record.
    fn change_of(&self, command: CreateRoleCommand) -> Result<IamChange, IamError> {
        let CreateRoleCommand {
            change_id,
            role_id,
            actor,
            name,
            description,
            idempotency,
        } = command;
        let now = self.clock.now();
        let fields = RoleFields::new(name, description)?;
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        let mut role = Role::create(role_id, fields, stamp);
        let events = role.pull_envelopes()?;
        let audit = self.audit(role.parts(), &actor, idempotency.as_ref(), now)?;
        let statement = RoleStatement::insert(&role, actor);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Unaffected,
            statements: vec![ChangeStatement::SaveRole(Box::new(statement))],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?)
    }

    /// The committed audit record of the creation.
    fn audit(
        &self,
        role: &RoleParts,
        actor: &ActorRef,
        idempotency: Option<&IdempotencyRequest>,
        now: SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("role", &role.id.to_string())?,
            scope: None,
            before: None,
            after: Some(AuditSummary::new(AUDIT_AFTER)?),
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
impl CommandHandler<CreateRoleCommand> for CreateRoleCommandHandler {
    async fn handle(&self, command: CreateRoleCommand) -> Result<(), IamError> {
        self.create(command).await
    }
}

#[cfg(test)]
mod tests;
