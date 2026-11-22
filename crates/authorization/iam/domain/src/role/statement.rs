//! The write of one role that a change hands to the unit of work.

use crate::role::{Role, RoleParts};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;

/// The write of one role: an insert, or an update guarded by the version the change read.
///
/// The unit of work stores the state of the role and its grants;
/// a grant that the role newly holds is recorded as granted by the actor at the time of the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStatement {
    role: RoleParts,
    expected: Option<EntityVersion>,
    actor: ActorRef,
}

impl RoleStatement {
    /// The insert of a new role; a stored role with the same identifier, or a role that is not
    /// deleted with the same name without regard to case, refuses it as a duplicate.
    #[must_use]
    pub fn insert(role: &Role, actor: ActorRef) -> Self {
        Self {
            role: role.parts().clone(),
            expected: None,
            actor,
        }
    }

    /// The update of a stored role that is not deleted and still holds the version `expected`;
    /// any other stored state refuses it as a conflict.
    #[must_use]
    pub fn update(role: &Role, expected: EntityVersion, actor: ActorRef) -> Self {
        Self {
            role: role.parts().clone(),
            expected: Some(expected),
            actor,
        }
    }

    /// The state of the role to store.
    #[must_use]
    pub const fn role(&self) -> &RoleParts {
        &self.role
    }

    /// The version the stored role must hold; `None` for an insert.
    #[must_use]
    pub const fn expected(&self) -> Option<EntityVersion> {
        self.expected
    }

    /// Who causes the write.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }
}

#[cfg(test)]
mod tests;
