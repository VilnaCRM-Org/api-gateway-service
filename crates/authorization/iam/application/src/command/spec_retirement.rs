//! The parts of a retirement that both catalogue forms share (FR-1, FR-2, FR-38).
//!
//! Retiring an active version removes its keys from the catalogue of its service unless another
//! active version holds them. Grants of keys that leave the catalogue are orphaned, which the
//! caller must confirm; the entries of those keys turn inactive.

use std::collections::BTreeSet;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, CatalogueActivation,
    CatalogueStatement, CatalogueStatementParts, ChangeId, ChangeStatement, DecisionEffect,
    EntityVersion, EntryFlags, EventEnvelope, GrantRecord, GuardCheck, IamChange, IamChangeParts,
    IdempotencyRequest, OrphanPolicy, PermissionCatalogue, PermissionFlags, PermissionKey,
    PermissionKeyKind, PermissionsOrphaned, PolicyVersion, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts, ServiceName, SpecId, SpecStatus, SpecTransition,
};
use shared_domain::UuidGenerator;

use super::create_graphql_permissions::{Confirmations, confirmed};
use crate::error::IamError;

/// A stored catalogue entry as a retirement sees it: its key, its flags and whether it is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredEntry {
    pub(crate) key: PermissionKey,
    pub(crate) flags: PermissionFlags,
    pub(crate) active: bool,
}

/// What a retirement is decided against.
pub(crate) struct Retirement {
    /// The form of the keys of the catalogue.
    pub(crate) kind: PermissionKeyKind,
    /// The version that is retired.
    pub(crate) spec_id: SpecId,
    /// The service of the version.
    pub(crate) service: ServiceName,
    /// When the version became active.
    pub(crate) activated_at: Option<SystemTime>,
    /// The catalogue of the active versions, the retired one included.
    pub(crate) previous: PermissionCatalogue,
    /// The catalogue of the active versions without the retired one.
    pub(crate) next: PermissionCatalogue,
    /// Every stored entry of the service.
    pub(crate) stored: Vec<StoredEntry>,
    /// Every grant of the catalogue of the service.
    pub(crate) grants: Vec<GrantRecord>,
    /// Whether the caller accepts that grants become inactive.
    pub(crate) confirm_orphans: bool,
    /// When the version is retired.
    pub(crate) at: SystemTime,
}

/// The outcome of the decision: what happens to the grants and the catalogue statement.
pub(crate) struct RetirementPlan {
    pub(crate) activation: CatalogueActivation,
    pub(crate) statement: CatalogueStatement,
}

/// Decides what the retirement does to the catalogue.
///
/// Keys that remain in the catalogue of the other active versions stay active; the flags of a key
/// follow the remaining versions.
///
/// # Errors
///
/// [`IamError::ConfirmationRequired`] that lists the orphaned grants when the caller did not
/// confirm them, and [`IamError`] for a statement that names a key of another service or form.
/// A retirement renames nothing, so no rename can be refused.
pub(crate) fn plan_retirement(input: Retirement) -> Result<RetirementPlan, IamError> {
    let activation =
        OrphanPolicy::apply_without_renames(&input.previous, &input.next, &input.grants);
    confirmed(
        &activation,
        Confirmations {
            flag_downgrade: true,
            orphans: input.confirm_orphans,
        },
    )?;
    let deactivated = deactivated_keys(&input.stored, &input.next);
    let reflagged = activation
        .flag_changes
        .iter()
        .map(|change| EntryFlags {
            key: change.key.clone(),
            flags: change.after,
        })
        .collect();
    let statement = CatalogueStatement::new(CatalogueStatementParts {
        kind: input.kind,
        service: input.service,
        transition: SpecTransition {
            spec_id: input.spec_id,
            from: SpecStatus::Active,
            to: SpecStatus::Retired,
            activated_at: input.activated_at,
            retired_at: Some(input.at),
        },
        created: Vec::new(),
        reflagged,
        reactivated: Vec::new(),
        deactivated,
        orphaned: activation.orphaned_grants.clone(),
        renames: Vec::new(),
        at: input.at,
    })?;
    Ok(RetirementPlan {
        activation,
        statement,
    })
}

/// The active stored entries of the scope of `next` that `next` lacks.
fn deactivated_keys(stored: &[StoredEntry], next: &PermissionCatalogue) -> Vec<PermissionKey> {
    let keys: BTreeSet<PermissionKey> = stored
        .iter()
        .filter(|entry| entry.active && next.is_in_scope(&entry.key) && !next.contains(&entry.key))
        .map(|entry| entry.key.clone())
        .collect();
    keys.into_iter().collect()
}

/// What the committed change of a retirement is made of.
pub(crate) struct RetirementChange<'a> {
    /// The identifier of the change.
    pub(crate) change_id: ChangeId,
    /// Who retires the version.
    pub(crate) actor: ActorRef,
    /// The policy version the retirement was decided against.
    pub(crate) locked: PolicyVersion,
    /// The idempotency key and request digest of the write.
    pub(crate) idempotency: Option<IdempotencyRequest>,
    /// The envelope of the version's own retirement event.
    pub(crate) spec_events: Vec<EventEnvelope>,
    /// The decided plan.
    pub(crate) plan: RetirementPlan,
    /// The audited action, such as `graphql_spec.retire`.
    pub(crate) action: &'static str,
    /// The audited target type, such as `graphql_spec`.
    pub(crate) target_type: &'static str,
    /// The retired version.
    pub(crate) spec_id: SpecId,
    /// The service of the version.
    pub(crate) service: ServiceName,
    /// When the version is retired.
    pub(crate) at: SystemTime,
    /// The source of identifiers.
    pub(crate) uuid_generator: &'a dyn UuidGenerator,
}

/// The change that retires the version: the policy guard, the catalogue statement, the events and
/// the audit record.
///
/// # Errors
///
/// [`IamError`] when an event, the audit record or the change is invalid.
pub(crate) fn retirement_change(mut input: RetirementChange<'_>) -> Result<IamChange, IamError> {
    let mut events = std::mem::take(&mut input.spec_events);
    let activation = &input.plan.activation;
    if !activation.orphaned_grants.is_empty() {
        events.push(EventEnvelope::of(&PermissionsOrphaned {
            event_id: input.uuid_generator.generate(),
            spec_id: input.spec_id,
            service: input.service.clone(),
            orphaned_keys: activation.orphaned_keys(),
            affected_role_ids: activation.affected_roles(),
            actor: input.actor.clone(),
            occurred_at: input.at,
        })?);
    }
    let audit = audit_record(&input)?;
    let guard = GuardCheck::Spec {
        service: input.service.clone(),
        flag_downgrade: !input.plan.activation.flag_downgrades.is_empty(),
    };
    Ok(IamChange::new(IamChangeParts {
        change_id: input.change_id,
        effect: DecisionEffect::Affected,
        statements: vec![
            ChangeStatement::ExpectPolicyVersion(input.locked),
            ChangeStatement::ApplyCatalogue(Box::new(input.plan.statement)),
        ],
        events,
        audit,
        entity_version: EntityVersion::INITIAL,
        idempotency: input.idempotency,
    })?
    .with_guard(guard))
}

/// The committed audit record of the retirement.
fn audit_record(input: &RetirementChange<'_>) -> Result<SecurityAuditEvent, IamError> {
    let after = format!(
        "service={} status=retired deactivated={} orphaned={}",
        input.service,
        input.plan.statement.parts().deactivated.len(),
        input.plan.activation.orphaned_grants.len()
    );
    let record = SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(input.uuid_generator.generate()),
        occurred_at: input.at,
        actor: input.actor.clone(),
        caller_service: None,
        action: AuditAction::new(input.action)?,
        target: AuditTarget::new(input.target_type, &input.spec_id.to_string())?,
        scope: None,
        before: Some(AuditSummary::new("status=active")?),
        after: Some(AuditSummary::new(&after)?),
        idempotency_key: input
            .idempotency
            .as_ref()
            .map(|request| request.key.clone()),
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: None,
        request_id: None,
    })?;
    Ok(record)
}

#[cfg(test)]
mod tests;
