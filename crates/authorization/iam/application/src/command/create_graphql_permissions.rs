//! Activates a GraphQL specification version and makes its fields grantable permissions (FR-1,
//! FR-2, FR-32).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, CatalogueActivation,
    CatalogueStatement, CatalogueStatementParts, ChangeId, ChangeStatement, CoordinateSet,
    DecisionEffect, EntityVersion, EntryFlags, EntryInsert, EventEnvelope, FlagChange,
    GraphQlPermission, GraphQlPermissionRepository, GraphQlPermissionsCreated, GraphQlSpec,
    GraphQlSpecRepository, IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest,
    OrphanPolicy, PermissionCatalogue, PermissionFlags, PermissionId, PermissionKey,
    PermissionKeyKind, PermissionsOrphaned, PolicyEpochRepository, PolicyVersion, RenameMap,
    RenameRefused, RoleRepository, SecurityAuditEvent, SecurityAuditEventId,
    SecurityAuditEventParts, ServiceName, SpecActivation, SpecId, SpecStatus, SpecTransition,
};
use shared_application::http::Violation;
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::{Confirmation, IamError};

/// The audit action of an activation.
const AUDIT_ACTION: &str = "graphql_spec.activate";

/// The command that activates the draft version `spec_id` as `actor`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateGraphQlPermissionsCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// Who activates the version.
    pub actor: ActorRef,
    /// The version to activate.
    pub spec_id: SpecId,
    /// The renames of coordinates that the version makes, as `(old key, new key)`.
    pub renames: Vec<(PermissionKey, PermissionKey)>,
    /// Whether the caller accepts that grants become inactive.
    pub confirm_orphans: bool,
    /// Whether the caller accepts that keys lose the sensitive or the always-audit flag.
    pub confirm_flag_downgrade: bool,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateGraphQlPermissionsCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateGraphQlPermissionsCommand";
}

/// The repositories that an activation reads before it decides.
#[derive(Debug, Clone)]
pub struct ActivationReads {
    /// The stored versions of the service.
    pub specs: Arc<dyn GraphQlSpecRepository>,
    /// The stored catalogue entries of the service.
    pub permissions: Arc<dyn GraphQlPermissionRepository>,
    /// The roles and their grants.
    pub roles: Arc<dyn RoleRepository>,
    /// The current policy epoch.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
}

/// Handles [`CreateGraphQlPermissionsCommand`].
///
/// It reads the version, the active versions of its service, the stored entries and the grants of
/// the service, computes what the activation does to the catalogue and, when the caller confirmed
/// what needs confirming, commits the status change, the entries, the orphaned and renamed grants,
/// the events and the audit record through the unit of work in one transaction. The change
/// affects decisions, so it takes the next policy version; it is guarded by the policy version it
/// was decided against. A version that is active already is a no-op that commits nothing.
#[derive(Debug)]
pub struct CreateGraphQlPermissionsCommandHandler {
    reads: ActivationReads,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl CreateGraphQlPermissionsCommandHandler {
    /// A handler over the repositories it reads, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        reads: ActivationReads,
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

    async fn activate(&self, command: CreateGraphQlPermissionsCommand) -> Result<(), IamError> {
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
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// What the activation does to the catalogue, once the caller confirmed what needs it.
    async fn plan(
        &self,
        spec: &GraphQlSpec,
        command: &CreateGraphQlPermissionsCommand,
    ) -> Result<Plan, IamError> {
        let service = spec.parts().content.service.clone();
        let mut coordinates: Vec<CoordinateSet> = self
            .reads
            .specs
            .find_active(&service)
            .await?
            .iter()
            .map(GraphQlSpec::coordinates)
            .collect();
        let previous = PermissionCatalogue::for_graphql(&service, &coordinates);
        coordinates.push(spec.coordinates());
        let next = PermissionCatalogue::for_graphql(&service, &coordinates);
        let stored = self.reads.permissions.find_by_service(&service).await?;
        let grants = self
            .reads
            .roles
            .find_catalogue_grants(&service, PermissionKeyKind::Gql)
            .await?;
        let renames =
            RenameMap::new(command.renames.clone()).map_err(|refusal| rename_refused(&refusal))?;
        let mut activation = OrphanPolicy::apply(&previous, &next, &renames, &grants)
            .map_err(|refusal| rename_refused(&refusal))?;
        let entries = self.entries(&stored, &next, &mut activation);
        confirmed(&activation, command)?;
        Ok(Plan {
            spec_id: spec.parts().id,
            service,
            activated_at: spec.parts().activated_at,
            activation,
            entries,
        })
    }

    /// The entries the activation creates, reactivates and re-flags.
    ///
    /// A stored entry that is inactive keeps its old flags until the activation makes it active
    /// again, so the flags it takes then count as flag changes of the activation.
    fn entries(
        &self,
        stored: &[GraphQlPermission],
        next: &PermissionCatalogue,
        activation: &mut CatalogueActivation,
    ) -> Entries {
        let known: BTreeMap<&PermissionKey, PermissionFlags> = stored
            .iter()
            .map(|entry| (&entry.parts().key, entry.parts().flags))
            .collect();
        let reactivated: Vec<PermissionKey> = activation
            .created_keys
            .iter()
            .filter(|key| known.contains_key(key))
            .cloned()
            .collect();
        let created = activation
            .created_keys
            .iter()
            .filter(|key| !known.contains_key(key))
            .filter_map(|key| {
                next.flags(key).map(|flags| EntryInsert {
                    id: PermissionId::from_uuid(self.uuid_generator.generate()),
                    key: key.clone(),
                    flags,
                })
            })
            .collect();
        activation
            .flag_changes
            .extend(regained_flags(&known, next, &reactivated));
        activation
            .flag_changes
            .sort_by(|left, right| left.key.cmp(&right.key));
        activation.flag_downgrades = activation
            .flag_changes
            .iter()
            .filter(|change| change.is_downgrade())
            .cloned()
            .collect();
        let reflagged = activation
            .flag_changes
            .iter()
            .map(|change| EntryFlags {
                key: change.key.clone(),
                flags: change.after,
            })
            .collect();
        Entries {
            created,
            reflagged,
            reactivated,
        }
    }

    /// The change that activates the version: the guard, the catalogue statement, the events and
    /// the audit record.
    fn change_of(
        &self,
        command: CreateGraphQlPermissionsCommand,
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
        let statement = catalogue_statement(plan, now)?;
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

    /// `iam.graphql_permissions.created`, and `iam.permissions.orphaned` when grants were orphaned.
    fn events(
        &self,
        context: &Context,
        activation: &CatalogueActivation,
    ) -> Result<Vec<EventEnvelope>, IamError> {
        let created = GraphQlPermissionsCreated {
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
        let after = format!(
            "service={} status=active created={} renamed={} flag_changes={} orphaned={}",
            context.service,
            activation.created_keys.len(),
            activation.renames.len(),
            activation.flag_changes.len(),
            activation.orphaned_grants.len()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: context.at,
            actor: context.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("graphql_spec", &context.spec_id.to_string())?,
            scope: None,
            before: Some(AuditSummary::new("status=draft")?),
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

/// Who activates which version of which service, and when.
struct Context {
    spec_id: SpecId,
    service: ServiceName,
    actor: ActorRef,
    at: SystemTime,
}

/// What the activation changes: the version, the effect on the catalogue and the entries.
struct Plan {
    spec_id: SpecId,
    service: ServiceName,
    activated_at: Option<SystemTime>,
    activation: CatalogueActivation,
    entries: Entries,
}

/// The catalogue entries an activation writes.
#[derive(Debug, Default)]
struct Entries {
    created: Vec<EntryInsert>,
    reflagged: Vec<EntryFlags>,
    reactivated: Vec<PermissionKey>,
}

/// The flag changes of the stored entries that the activation makes active again: their stored
/// flags against the flags of the catalogue that takes effect.
fn regained_flags(
    known: &BTreeMap<&PermissionKey, PermissionFlags>,
    next: &PermissionCatalogue,
    reactivated: &[PermissionKey],
) -> Vec<FlagChange> {
    reactivated
        .iter()
        .filter_map(|key| {
            let before = *known.get(key)?;
            let after = next.flags(key)?;
            (before != after).then(|| FlagChange {
                key: key.clone(),
                before,
                after,
            })
        })
        .collect()
}

/// The catalogue statement of the plan, taking effect at `now`.
fn catalogue_statement(plan: Plan, now: SystemTime) -> Result<CatalogueStatement, IamError> {
    let Plan {
        spec_id,
        service,
        activated_at,
        activation,
        entries,
    } = plan;
    CatalogueStatement::new(CatalogueStatementParts {
        kind: PermissionKeyKind::Gql,
        service,
        transition: SpecTransition {
            spec_id,
            from: SpecStatus::Draft,
            to: SpecStatus::Active,
            activated_at,
            retired_at: None,
        },
        created: entries.created,
        reflagged: entries.reflagged,
        reactivated: entries.reactivated,
        deactivated: Vec::new(),
        orphaned: activation.orphaned_grants,
        renames: activation.renames,
        at: now,
    })
    .map_err(IamError::from)
}

/// Checks that the caller confirmed the flag downgrades and the orphaned grants the activation
/// causes.
///
/// # Errors
///
/// [`IamError::ConfirmationRequired`] that lists the keys of the first unconfirmed kind: the flag
/// downgrades, then the orphaned grants.
fn confirmed(
    activation: &CatalogueActivation,
    command: &CreateGraphQlPermissionsCommand,
) -> Result<(), IamError> {
    if !command.confirm_flag_downgrade && !activation.flag_downgrades.is_empty() {
        let items = activation
            .flag_downgrades
            .iter()
            .map(|change| Violation {
                property_path: change.key.to_string(),
                message: "This key would lose the sensitive or the always-audit flag.".to_owned(),
                code: "flag_downgrade".to_owned(),
            })
            .collect();
        return Err(IamError::ConfirmationRequired(
            Confirmation::FlagDowngrade,
            items,
        ));
    }
    if !command.confirm_orphans && !activation.orphaned_grants.is_empty() {
        let items = activation
            .orphaned_grants
            .iter()
            .map(|grant| Violation {
                property_path: grant.key.to_string(),
                message: format!("The role {} grants this key.", grant.role),
                code: "orphaned_grant".to_owned(),
            })
            .collect();
        return Err(IamError::ConfirmationRequired(Confirmation::Orphans, items));
    }
    Ok(())
}

/// The violation of `renames` that a refused rename is.
fn rename_refused(refusal: &RenameRefused) -> IamError {
    IamError::invalid_property("renames", &refusal.to_string(), "rename")
}

#[async_trait::async_trait]
impl CommandHandler<CreateGraphQlPermissionsCommand> for CreateGraphQlPermissionsCommandHandler {
    async fn handle(&self, command: CreateGraphQlPermissionsCommand) -> Result<(), IamError> {
        self.activate(command).await
    }
}

#[cfg(test)]
mod tests;
