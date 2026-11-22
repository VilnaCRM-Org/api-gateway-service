//! The description of one administrative change that the unit of work commits atomically.

use crate::entity::change_receipt::ChangeReceipt;
use crate::entity::event_envelope::EventEnvelope;
use crate::entity::idempotency_record::{IdempotencyRecord, IdempotencyRequest};
use crate::entity::security_audit_event::SecurityAuditEvent;
use crate::error::InvalidIamValue;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::change_statement::ChangeStatement;
use crate::value_object::decision_effect::DecisionEffect;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::ChangeId;
use crate::value_object::policy_version::PolicyVersion;

/// The values of a change, as a command handler assembles them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IamChangeParts {
    /// The identifier of the change, from the `UuidGenerator` port.
    pub change_id: ChangeId,
    /// Whether the change affects decisions, and whether it takes access away.
    pub effect: DecisionEffect,
    /// The aggregate statements and guards, in order.
    pub statements: Vec<ChangeStatement>,
    /// The envelopes of the pulled domain events, in order.
    pub events: Vec<EventEnvelope>,
    /// The committed audit record of the change; the unit of work stamps its policy version.
    pub audit: SecurityAuditEvent,
    /// The version of the changed record after the change.
    pub entity_version: EntityVersion,
    /// The idempotency key and request digest, when the write carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

/// One administrative change: its statements, its events, its audit record, its change receipt and
/// its idempotency record, committed together under one policy version or not at all (FR-2,
/// FR-49).
///
/// The actor and target of the receipt and of the idempotency record are those of the audit record,
/// and its time is the time of the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IamChange(IamChangeParts);

impl IamChange {
    /// Validates the change.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ChangeAuditOutcome`] when the audit record is not committed.
    pub fn new(parts: IamChangeParts) -> Result<Self, InvalidIamValue> {
        if parts.audit.parts().outcome != AuditOutcome::Committed {
            return Err(InvalidIamValue::ChangeAuditOutcome);
        }
        Ok(Self(parts))
    }

    /// The values of the change.
    #[must_use]
    pub const fn parts(&self) -> &IamChangeParts {
        &self.0
    }

    /// Whether the change takes the next policy version.
    #[must_use]
    pub const fn affects_decisions(&self) -> bool {
        self.0.effect.affects_decisions()
    }

    /// Whether the change takes access away.
    #[must_use]
    pub const fn is_revocation_class(&self) -> bool {
        self.0.effect.is_revocation_class()
    }

    /// When the change happened, in whole microseconds since 1970.
    #[must_use]
    pub const fn occurred_at_micros(&self) -> i64 {
        self.0.audit.occurred_at_micros()
    }

    /// The policy version the change produced when the transaction holds `version`: that version
    /// when the change affects decisions, none otherwise.
    #[must_use]
    pub const fn resulting_policy_version(&self, version: PolicyVersion) -> Option<PolicyVersion> {
        if self.affects_decisions() {
            Some(version)
        } else {
            None
        }
    }

    /// The audit record stamped with the policy version the change produced.
    #[must_use]
    pub fn audit(&self, version: PolicyVersion) -> SecurityAuditEvent {
        self.0
            .audit
            .with_policy_version(self.resulting_policy_version(version))
    }

    /// The receipt of the change when the transaction holds `version`.
    #[must_use]
    pub fn receipt(&self, version: PolicyVersion) -> ChangeReceipt {
        let audit = self.0.audit.parts();
        ChangeReceipt::new(
            self.0.change_id,
            audit.actor.clone(),
            audit.target.clone(),
            self.0.entity_version,
            self.resulting_policy_version(version),
        )
    }

    /// The idempotency record of the change, when the write carries a key.
    #[must_use]
    pub fn idempotency_record(&self) -> Option<IdempotencyRecord> {
        self.0.idempotency.clone().map(|request| {
            IdempotencyRecord::new(
                self.0.audit.parts().actor.clone(),
                request,
                self.0.change_id,
            )
        })
    }
}

#[cfg(test)]
mod tests;
