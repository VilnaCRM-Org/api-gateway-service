//! The receipt of a committed administrative change.

use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::ChangeId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::propagation_outcome::PropagationOutcome;

/// The result of a committed change: REST and GraphQL read it after a command that returns no
/// data, and a replay with the same idempotency key returns it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeReceipt {
    change_id: ChangeId,
    actor: ActorRef,
    target: AuditTarget,
    entity_version: EntityVersion,
    policy_version: Option<PolicyVersion>,
    revoked_assignments: Option<u32>,
    propagation: Option<PropagationOutcome>,
}

impl ChangeReceipt {
    /// Records the result of the change `change_id`.
    #[must_use]
    pub const fn new(
        change_id: ChangeId,
        actor: ActorRef,
        target: AuditTarget,
        entity_version: EntityVersion,
        policy_version: Option<PolicyVersion>,
    ) -> Self {
        Self {
            change_id,
            actor,
            target,
            entity_version,
            policy_version,
            revoked_assignments: None,
            propagation: None,
        }
    }

    /// The same receipt, reporting that the change revoked `count` assignments.
    #[must_use]
    pub const fn with_revoked_assignments(mut self, count: u32) -> Self {
        self.revoked_assignments = Some(count);
        self
    }

    /// The same receipt, carrying what the write learned about the publication of its policy
    /// version.
    #[must_use]
    pub const fn with_propagation(mut self, outcome: PropagationOutcome) -> Self {
        self.propagation = Some(outcome);
        self
    }

    /// The change.
    #[must_use]
    pub const fn change_id(&self) -> ChangeId {
        self.change_id
    }

    /// Who made the change.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }

    /// The changed record.
    #[must_use]
    pub const fn target(&self) -> &AuditTarget {
        &self.target
    }

    /// The version of the changed record after the change, the source of the `ETag`.
    #[must_use]
    pub const fn entity_version(&self) -> EntityVersion {
        self.entity_version
    }

    /// The policy version the change produced; none when the change did not affect decisions.
    #[must_use]
    pub const fn policy_version(&self) -> Option<PolicyVersion> {
        self.policy_version
    }

    /// The number of assignments the change revoked; none when the change is not the deletion of
    /// a role.
    #[must_use]
    pub const fn revoked_assignments(&self) -> Option<u32> {
        self.revoked_assignments
    }

    /// What the write learned about the publication of its policy version; none when the change
    /// does not affect decisions, so it waited for nothing.
    #[must_use]
    pub const fn propagation(&self) -> Option<PropagationOutcome> {
        self.propagation
    }
}

#[cfg(test)]
mod tests;
