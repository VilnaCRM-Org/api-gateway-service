//! The receipt of a committed administrative change.

use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::ChangeId;
use crate::value_object::policy_version::PolicyVersion;

/// The result of a committed change: REST and GraphQL read it after a command that returns no
/// data, and a replay with the same idempotency key returns it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeReceipt {
    change_id: ChangeId,
    actor: ActorRef,
    target: AuditTarget,
    entity_version: EntityVersion,
    policy_version: Option<PolicyVersion>,
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
        }
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
}

#[cfg(test)]
mod tests;
