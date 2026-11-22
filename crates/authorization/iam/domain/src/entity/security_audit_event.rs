//! The security audit record and its place in the hash chain.

use std::time::{Duration, SystemTime};

use crate::error::InvalidIamValue;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_hash::AuditHash;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::audit_reason::AuditReason;
use crate::value_object::audit_summary::AuditSummary;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::SecurityAuditEventId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::request_id::RequestId;
use crate::value_object::service_name::ServiceName;

/// The first line of the canonical form; it names the layout, so a later layout can be told apart.
const CANONICAL_HEADER: &str = "iam.security_audit.v1";

/// The values of a security audit record, as the recording code assembles them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditEventParts {
    /// The identifier of the record, from the `UuidGenerator` port.
    pub id: SecurityAuditEventId,
    /// When the action happened, from the `Clock` port.
    pub occurred_at: SystemTime,
    /// Who performed the action.
    pub actor: ActorRef,
    /// The service that called on behalf of the actor, when it differs from the actor.
    pub caller_service: Option<ServiceName>,
    /// What was done.
    pub action: AuditAction,
    /// What it was done to.
    pub target: AuditTarget,
    /// Where it applies.
    pub scope: Option<AssignmentScope>,
    /// The state before the change.
    pub before: Option<AuditSummary>,
    /// The state after the change.
    pub after: Option<AuditSummary>,
    /// The idempotency key of the write.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Whether the change took effect.
    pub outcome: AuditOutcome,
    /// Why an attempt was refused.
    pub reason: Option<AuditReason>,
    /// The policy version that resulted from the change.
    pub policy_version: Option<PolicyVersion>,
    /// The caller's request id.
    pub request_id: Option<RequestId>,
}

/// One append-only security audit record (FR-49).
///
/// Its time is kept in whole microseconds, the precision of the store, so a record read back has
/// the same canonical form as the record that was appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditEvent {
    parts: SecurityAuditEventParts,
    occurred_at_micros: i64,
}

impl SecurityAuditEvent {
    /// Records the values: the time is truncated to microseconds and a caller service equal to the
    /// actor's own service name is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditTimestamp`] when the time lies before 1970 or past the
    /// largest number of microseconds in 64 bits.
    pub fn record(mut parts: SecurityAuditEventParts) -> Result<Self, InvalidIamValue> {
        let occurred_at_micros = micros_since_epoch(parts.occurred_at)?;
        parts.occurred_at = time_of(occurred_at_micros)?;
        if let ActorRef::Service(actor) = &parts.actor
            && parts.caller_service.as_ref() == Some(actor)
        {
            parts.caller_service = None;
        }
        Ok(Self {
            parts,
            occurred_at_micros,
        })
    }

    /// Rebuilds a stored record from its time in microseconds since 1970.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditTimestamp`] when `occurred_at_micros` is negative.
    pub fn restore(
        parts: SecurityAuditEventParts,
        occurred_at_micros: i64,
    ) -> Result<Self, InvalidIamValue> {
        let occurred_at = time_of(occurred_at_micros)?;
        Self::record(SecurityAuditEventParts {
            occurred_at,
            ..parts
        })
    }

    /// The values of the record.
    #[must_use]
    pub const fn parts(&self) -> &SecurityAuditEventParts {
        &self.parts
    }

    /// When the action happened, in whole microseconds since 1970.
    #[must_use]
    pub const fn occurred_at_micros(&self) -> i64 {
        self.occurred_at_micros
    }

    /// The canonical form that the hash chain digests: a header line, then one `name=value` line
    /// per value in a fixed order, an absent value written as nothing after `=`.
    ///
    /// No value can hold a line break, so the form is unambiguous.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        let parts = &self.parts;
        let lines = [
            ("id", parts.id.to_string()),
            ("occurred_at", self.occurred_at_micros.to_string()),
            ("actor", parts.actor.to_string()),
            ("caller_service", text(parts.caller_service.as_ref())),
            ("action", parts.action.to_string()),
            ("target_type", parts.target.target_type().to_owned()),
            ("target_id", parts.target.target_id().to_owned()),
            ("scope", text(parts.scope.as_ref())),
            (
                "before",
                text(parts.before.as_ref().map(AuditSummary::as_str)),
            ),
            (
                "after",
                text(parts.after.as_ref().map(AuditSummary::as_str)),
            ),
            ("idempotency_key", text(parts.idempotency_key.as_ref())),
            ("outcome", parts.outcome.as_str().to_owned()),
            (
                "reason",
                text(parts.reason.as_ref().map(AuditReason::as_str)),
            ),
            (
                "policy_version",
                text(parts.policy_version.map(PolicyVersion::value)),
            ),
            ("request_id", text(parts.request_id.as_ref())),
        ];
        lines
            .iter()
            .fold(CANONICAL_HEADER.to_owned(), |form, (name, value)| {
                format!("{form}\n{name}={value}")
            })
    }
}

/// A security audit record with its place in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecurityAuditEvent {
    seq: i64,
    event: SecurityAuditEvent,
    prev_hash: AuditHash,
    hash: AuditHash,
}

impl StoredSecurityAuditEvent {
    /// Places the record in the chain.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditSequence`] when `seq` is below 1.
    pub fn new(
        seq: i64,
        event: SecurityAuditEvent,
        prev_hash: AuditHash,
        hash: AuditHash,
    ) -> Result<Self, InvalidIamValue> {
        if seq < 1 {
            return Err(InvalidIamValue::AuditSequence);
        }
        Ok(Self {
            seq,
            event,
            prev_hash,
            hash,
        })
    }

    /// The gap-free sequence number, starting at 1.
    #[must_use]
    pub const fn seq(&self) -> i64 {
        self.seq
    }

    /// The record.
    #[must_use]
    pub const fn event(&self) -> &SecurityAuditEvent {
        &self.event
    }

    /// The hash of the previous record, the genesis hash for the first one.
    #[must_use]
    pub const fn prev_hash(&self) -> AuditHash {
        self.prev_hash
    }

    /// `SHA-256(prev_hash || canonical_form)`.
    #[must_use]
    pub const fn hash(&self) -> AuditHash {
        self.hash
    }
}

/// The text of an optional value, empty when it is absent.
fn text<T: ToString>(value: Option<T>) -> String {
    value.map(|present| present.to_string()).unwrap_or_default()
}

/// Whole microseconds since 1970.
fn micros_since_epoch(time: SystemTime) -> Result<i64, InvalidIamValue> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .ok_or(InvalidIamValue::AuditTimestamp)
}

/// The time `micros` microseconds after 1970.
fn time_of(micros: i64) -> Result<SystemTime, InvalidIamValue> {
    u64::try_from(micros)
        .ok()
        .and_then(|micros| SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros)))
        .ok_or(InvalidIamValue::AuditTimestamp)
}

#[cfg(test)]
mod tests;
