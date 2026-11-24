//! Activates an `OpenAPI` specification version and makes its operations grantable permissions
//! (FR-1, FR-2, FR-36).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditTarget, CatalogueActivation, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, EventEnvelope, IamChange, IamChangeParts, IamUnitOfWork,
    IdempotencyRequest, OpenApiSpec, OpenApiSpecRepository, OrphanPolicy, PermissionCatalogue,
    PermissionKey, PermissionKeyKind, PermissionsOrphaned, PolicyEpochRepository, PolicyVersion,
    RenameMap, RestPermissionRepository, RestPermissionsCreated, RoleRepository,
    SecurityAuditEvent, SpecActivation, SpecId,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_graphql_permissions::{
    Confirmations, Context, Plan, activation_audit, catalogue_statement, confirmed, plan_entries,
    rename_refused,
};
use crate::error::IamError;

/// The audit action of an activation.
const AUDIT_ACTION: &str = "openapi_spec.activate";

/// The command that activates the draft version `spec_id` as `actor`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateRestPermissionsCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// Who activates the version.
    pub actor: ActorRef,
    /// The version to activate.
    pub spec_id: SpecId,
    /// The renames of operations that the version makes, as `(old key, new key)`.
    pub renames: Vec<(PermissionKey, PermissionKey)>,
    /// Whether the caller accepts that grants become inactive.
    pub confirm_orphans: bool,
    /// Whether the caller accepts that keys lose the sensitive or the always-audit flag.
    pub confirm_flag_downgrade: bool,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateRestPermissionsCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateRestPermissionsCommand";
}

/// The repositories that an activation of an `OpenAPI` version reads before it decides.
#[derive(Debug, Clone)]
pub struct RestActivationReads {
    /// The stored versions of the service.
    pub specs: Arc<dyn OpenApiSpecRepository>,
    /// The stored catalogue entries of the service.
    pub permissions: Arc<dyn RestPermissionRepository>,
    /// The roles and their grants.
    pub roles: Arc<dyn RoleRepository>,
    /// The current policy epoch.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
}

/// Handles [`CreateRestPermissionsCommand`].
///
/// It reads the version, the active versions of its service, the stored entries and the grants of
/// the service, computes what the activation does to the catalogue and, when the caller confirmed
/// what needs confirming, commits the status change, the entries, the orphaned and renamed grants,
/// the events and the audit record through the unit of work in one transaction. The change
/// affects decisions, so it takes the next policy version; it is guarded by the policy version it
/// was decided against. A version that is active already is a no-op that commits nothing.
#[derive(Debug)]
pub struct CreateRestPermissionsCommandHandler {
    reads: RestActivationReads,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl CreateRestPermissionsCommandHandler {
    /// A handler over the repositories it reads, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        reads: RestActivationReads,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            reads,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn activate(&self, command: CreateRestPermissionsCommand) -> Result<(), IamError> {
        let mut spec = self
            .reads
            .specs
            .find_by_id(command.spec_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let now = self.clock.now();
        let activation = spec.activate(now).map_err(|_refused| IamError::Conflict)?;
        if activation == SpecActivation::AlreadyActive {
            return Ok(());
        }
        let epoch = self.reads.policy_epochs.current().await?;
        let plan = self.plan(&spec, &command).await?;
        let change = self.change_of(command, plan, epoch.version(), now)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// What the activation does to the catalogue, once the caller confirmed what needs it.
    async fn plan(
        &self,
        spec: &OpenApiSpec,
        command: &CreateRestPermissionsCommand,
    ) -> Result<Plan, IamError> {
        let service = spec.parts().content.service.clone();
        let active = self.reads.specs.find_active(&service).await?;
        let previous =
            PermissionCatalogue::for_rest(&service, active.iter().map(OpenApiSpec::operations));
        let next = PermissionCatalogue::for_rest(
            &service,
            active
                .iter()
                .map(OpenApiSpec::operations)
                .chain([spec.operations()]),
        );
        let stored = self.reads.permissions.find_by_service(&service).await?;
        let grants = self
            .reads
            .roles
            .find_catalogue_grants(&service, PermissionKeyKind::Rest)
            .await?;
        let renames =
            RenameMap::new(command.renames.clone()).map_err(|refusal| rename_refused(&refusal))?;
        let mut activation = OrphanPolicy::apply(&previous, &next, &renames, &grants)
            .map_err(|refusal| rename_refused(&refusal))?;
        let known = stored
            .iter()
            .map(|entry| (&entry.parts().key, entry.parts().flags))
            .collect();
        let entries = plan_entries(&known, &next, &mut activation, self.uuid_generator.as_ref());
        confirmed(
            &activation,
            Confirmations {
                flag_downgrade: command.confirm_flag_downgrade,
                orphans: command.confirm_orphans,
            },
        )?;
        Ok(Plan {
            spec_id: spec.parts().id,
            service,
            activated_at: spec.parts().activated_at,
            activation,
            entries,
        })
    }

    /// The change that activates the version: the guard, the catalogue statement, the events and
    /// the audit record.
    fn change_of(
        &self,
        command: CreateRestPermissionsCommand,
        plan: Plan,
        locked: PolicyVersion,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let context = Context {
            spec_id: plan.spec_id,
            service: plan.service.clone(),
            actor: command.actor,
            at: now,
        };
        let events = self.events(&context, &plan.activation)?;
        let audit = self.audit(&context, &plan.activation, command.idempotency.as_ref())?;
        let statement = catalogue_statement(PermissionKeyKind::Rest, plan, now)?;
        Ok(IamChange::new(IamChangeParts {
            change_id: command.change_id,
            effect: DecisionEffect::Affected,
            statements: vec![
                ChangeStatement::ExpectPolicyVersion(locked),
                ChangeStatement::ApplyCatalogue(Box::new(statement)),
            ],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: command.idempotency,
        })?)
    }

    /// `iam.rest_permissions.created`, and `iam.permissions.orphaned` when grants were orphaned.
    fn events(
        &self,
        context: &Context,
        activation: &CatalogueActivation,
    ) -> Result<Vec<EventEnvelope>, IamError> {
        let created = RestPermissionsCreated {
            event_id: self.uuid_generator.generate(),
            spec_id: context.spec_id,
            service: context.service.clone(),
            created_keys: activation.created_keys.clone(),
            renamed: activation.renames.clone(),
            flag_changes: activation.flag_changes.clone(),
            actor: context.actor.clone(),
            occurred_at: context.at,
        };
        let mut events = vec![EventEnvelope::of(&created)?];
        if !activation.orphaned_grants.is_empty() {
            let orphaned = PermissionsOrphaned {
                event_id: self.uuid_generator.generate(),
                spec_id: context.spec_id,
                service: context.service.clone(),
                orphaned_keys: activation.orphaned_keys(),
                affected_role_ids: activation.affected_roles(),
                actor: context.actor.clone(),
                occurred_at: context.at,
            };
            events.push(EventEnvelope::of(&orphaned)?);
        }
        Ok(events)
    }

    /// The committed audit record of the activation.
    fn audit(
        &self,
        context: &Context,
        activation: &CatalogueActivation,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let target = AuditTarget::new("openapi_spec", &context.spec_id.to_string())?;
        activation_audit(
            self.uuid_generator.as_ref(),
            AuditAction::new(AUDIT_ACTION)?,
            target,
            (context, activation),
            idempotency,
        )
    }
}

#[async_trait::async_trait]
impl CommandHandler<CreateRestPermissionsCommand> for CreateRestPermissionsCommandHandler {
    async fn handle(&self, command: CreateRestPermissionsCommand) -> Result<(), IamError> {
        self.activate(command).await
    }
}

#[cfg(test)]
mod tests;
