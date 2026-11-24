//! The description of one administrative change that the unit of work commits atomically.

use crate::entity::change_receipt::ChangeReceipt;
use crate::entity::event_envelope::EventEnvelope;
use crate::entity::idempotency_record::{IdempotencyRecord, IdempotencyRequest};
use crate::entity::security_audit_event::SecurityAuditEvent;
use crate::error::InvalidIamValue;
use crate::policy::change_guard::GuardCheck;
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
pub struct IamChange {
    parts: IamChangeParts,
    revoked_assignments: Option<u32>,
    related_audits: Vec<SecurityAuditEvent>,
    guard: Option<GuardCheck>,
}

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
        Ok(Self {
            parts,
            revoked_assignments: None,
            related_audits: Vec::new(),
            guard: None,
        })
    }

    /// The same change, whose receipt reports that it revoked `count` assignments (the deletion
    /// of a role revokes every assignment of it).
    #[must_use]
    pub const fn with_revoked_assignments(mut self, count: u32) -> Self {
        self.revoked_assignments = Some(count);
        self
    }

    /// The same change, which also appends `audits` after its own audit record: one record for
    /// each other record that the change writes (the assignments a role deletion revokes). Every
    /// record must be committed.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ChangeAuditOutcome`] when one of the records is not committed.
    pub fn with_related_audits(
        mut self,
        audits: Vec<SecurityAuditEvent>,
    ) -> Result<Self, InvalidIamValue> {
        if audits
            .iter()
            .any(|audit| audit.parts().outcome != AuditOutcome::Committed)
        {
            return Err(InvalidIamValue::ChangeAuditOutcome);
        }
        self.related_audits = audits;
        Ok(self)
    }

    /// The same change, which asks the unit of work to run `check` for its actor against the
    /// stored policy before it commits.
    #[must_use]
    pub fn with_guard(mut self, check: GuardCheck) -> Self {
        self.guard = Some(check);
        self
    }

    /// The same change that also holds when the policy version is still `version`: the version
    /// the guard decided against, which the transaction compares with the version it locked.
    #[must_use]
    pub fn expecting_policy_version(mut self, version: PolicyVersion) -> Self {
        self.parts
            .statements
            .push(ChangeStatement::ExpectPolicyVersion(version));
        self
    }

    /// The check the change asks for, when it asks for one.
    #[must_use]
    pub const fn guard(&self) -> Option<&GuardCheck> {
        self.guard.as_ref()
    }

    /// The number of assignments the change revokes, when it reports one.
    #[must_use]
    pub const fn revoked_assignments(&self) -> Option<u32> {
        self.revoked_assignments
    }

    /// The values of the change.
    #[must_use]
    pub const fn parts(&self) -> &IamChangeParts {
        &self.parts
    }

    /// Whether the change takes the next policy version.
    #[must_use]
    pub const fn affects_decisions(&self) -> bool {
        self.parts.effect.affects_decisions()
    }

    /// Whether the change takes access away.
    #[must_use]
    pub const fn is_revocation_class(&self) -> bool {
        self.parts.effect.is_revocation_class()
    }

    /// When the change happened, in whole microseconds since 1970.
    #[must_use]
    pub const fn occurred_at_micros(&self) -> i64 {
        self.parts.audit.occurred_at_micros()
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
        self.parts
            .audit
            .with_policy_version(self.resulting_policy_version(version))
    }

    /// Every audit record of the change in write order, each stamped with the policy version the
    /// change produced: its own record first, then the related ones.
    #[must_use]
    pub fn audits(&self, version: PolicyVersion) -> Vec<SecurityAuditEvent> {
        let produced = self.resulting_policy_version(version);
        std::iter::once(self.audit(version))
            .chain(
                self.related_audits
                    .iter()
                    .map(|audit| audit.with_policy_version(produced)),
            )
            .collect()
    }

    /// The receipt of the change when the transaction holds `version`.
    #[must_use]
    pub fn receipt(&self, version: PolicyVersion) -> ChangeReceipt {
        let audit = self.parts.audit.parts();
        let receipt = ChangeReceipt::new(
            self.parts.change_id,
            audit.actor.clone(),
            audit.target.clone(),
            self.parts.entity_version,
            self.resulting_policy_version(version),
        );
        match self.revoked_assignments {
            Some(count) => receipt.with_revoked_assignments(count),
            None => receipt,
        }
    }

    /// The idempotency record of the change, when the write carries a key.
    #[must_use]
    pub fn idempotency_record(&self) -> Option<IdempotencyRecord> {
        self.parts.idempotency.clone().map(|request| {
            IdempotencyRecord::new(
                self.parts.audit.parts().actor.clone(),
                request,
                self.parts.change_id,
            )
        })
    }
}

#[cfg(test)]
mod tests;
