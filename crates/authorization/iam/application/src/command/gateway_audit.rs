//! The audit records of the changes of the gateway configuration (upstreams, routes, rate
//! policies) and the refusals of the entries that IAM manages itself.

use std::time::SystemTime;

use iam_domain::{
    ActorRef, AnonymousRouteRefused, AuditAction, AuditOutcome, AuditReason, AuditSummary,
    AuditTarget, IdempotencyRequest, RejectedAttempt, RejectedAttemptLog, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts,
};
use shared_domain::UuidGenerator;

use crate::error::IamError;

/// The reason that the rejected record of a refused change of a system entry carries.
const SYSTEM_ENTRY_REASON: &str = "system_entry";

/// The reason that the rejected record of a change whose actor lacks the route key of the
/// catalogue service carries; the unit of work records the same reason for its own refusals.
const ROUTE_SCOPE_REASON: &str = "route_scope.denied";

/// What the committed audit record of a change of one entry says.
#[derive(Debug)]
pub(crate) struct ChangeRecord<'a> {
    /// The audited action, such as `upstream.create`.
    pub action: &'static str,
    /// The kind of the entry, such as `upstream`.
    pub kind: &'static str,
    /// The identifier of the entry.
    pub target_id: String,
    /// Who made the change.
    pub actor: &'a ActorRef,
    /// When the change happened.
    pub occurred_at: SystemTime,
    /// The state before the change; none for a creation.
    pub before: Option<String>,
    /// The state after the change.
    pub after: String,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<&'a IdempotencyRequest>,
}

/// The committed audit record of the change.
///
/// # Errors
///
/// [`IamError::Internal`] when a value of the record breaks an invariant of the domain.
pub(crate) fn committed(
    ids: &dyn UuidGenerator,
    record: ChangeRecord<'_>,
) -> Result<SecurityAuditEvent, IamError> {
    let ChangeRecord {
        action,
        kind,
        target_id,
        actor,
        occurred_at,
        before,
        after,
        idempotency,
    } = record;
    let parts = SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(ids.generate()),
        occurred_at,
        actor: actor.clone(),
        caller_service: None,
        action: AuditAction::new(action)?,
        target: AuditTarget::new(kind, &target_id)?,
        scope: None,
        before: before.as_deref().map(AuditSummary::new).transpose()?,
        after: Some(AuditSummary::new(&after)?),
        idempotency_key: idempotency.map(|request| request.key.clone()),
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: None,
        request_id: None,
    };
    Ok(SecurityAuditEvent::record(parts)?)
}

/// The refusal of a change of an entry that IAM manages itself.
#[derive(Debug)]
pub(crate) struct SystemEntryRefusal<'a> {
    /// The audited action that was refused.
    pub action: &'static str,
    /// The kind of the entry, such as `upstream`.
    pub kind: &'static str,
    /// The identifier of the entry.
    pub target_id: String,
    /// Who asked for the change.
    pub actor: &'a ActorRef,
    /// When it was refused.
    pub occurred_at: SystemTime,
}

/// Offers the refusal to the buffer of the audit log and returns the error that answers the
/// caller: [`IamError::SystemEntry`].
///
/// # Errors
///
/// [`IamError::Internal`] when a value of the record breaks an invariant of the domain; the
/// refusal is not recorded then.
pub(crate) fn refuse_system_entry(
    log: &dyn RejectedAttemptLog,
    refusal: SystemEntryRefusal<'_>,
) -> IamError {
    offer(log, refusal, SYSTEM_ENTRY_REASON, IamError::SystemEntry)
}

/// Offers the refusal of an actor without the route key of the catalogue service to the buffer of
/// the audit log and returns the error that answers the caller: [`IamError::Forbidden`].
///
/// # Errors
///
/// [`IamError::Internal`] when a value of the record breaks an invariant of the domain; the
/// refusal is not recorded then.
pub(crate) fn refuse_route_scope(
    log: &dyn RejectedAttemptLog,
    refusal: SystemEntryRefusal<'_>,
) -> IamError {
    offer(log, refusal, ROUTE_SCOPE_REASON, IamError::Forbidden)
}

/// Offers the refusal of an actor without `iam:route:anonymous` to the buffer of the audit log
/// and returns the error that answers the caller: [`IamError::Forbidden`].
///
/// # Errors
///
/// [`IamError::Internal`] when a value of the record breaks an invariant of the domain; the
/// refusal is not recorded then.
pub(crate) fn refuse_anonymous_route(
    log: &dyn RejectedAttemptLog,
    refusal: SystemEntryRefusal<'_>,
) -> IamError {
    offer(
        log,
        refusal,
        AnonymousRouteRefused::CODE,
        IamError::Forbidden,
    )
}

/// Records the refusal with its reason and answers with `error`.
fn offer(
    log: &dyn RejectedAttemptLog,
    refusal: SystemEntryRefusal<'_>,
    reason: &str,
    error: IamError,
) -> IamError {
    match rejected(refusal, reason) {
        Ok(attempt) => {
            log.offer(attempt);
            error
        }
        Err(error) => error,
    }
}

/// The rejected attempt that the refusal records.
fn rejected(refusal: SystemEntryRefusal<'_>, reason: &str) -> Result<RejectedAttempt, IamError> {
    let SystemEntryRefusal {
        action,
        kind,
        target_id,
        actor,
        occurred_at,
    } = refusal;
    Ok(RejectedAttempt {
        actor: actor.clone(),
        action: AuditAction::new(action)?,
        reason: AuditReason::new(reason)?,
        target: AuditTarget::new(kind, &target_id)?,
        occurred_at,
        request_id: None,
    })
}

#[cfg(test)]
mod tests;
