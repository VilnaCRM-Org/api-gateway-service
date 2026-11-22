//! The write of one assignment that a change hands to the unit of work.

use crate::user_role::{UserRole, UserRoleParts};
use crate::value_object::entity_version::EntityVersion;

/// The write of one assignment: an insert, or an update guarded by the version the change read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleStatement {
    user_role: UserRoleParts,
    expected: Option<EntityVersion>,
}

impl UserRoleStatement {
    /// The insert of a new assignment; a stored assignment with the same identifier, or one that
    /// is not revoked with the same subject, role and scope, refuses it as a duplicate.
    #[must_use]
    pub fn insert(user_role: &UserRole) -> Self {
        Self {
            user_role: user_role.parts().clone(),
            expected: None,
        }
    }

    /// The update of a stored assignment that is not revoked and still holds the version
    /// `expected`; any other stored state refuses it as a conflict.
    #[must_use]
    pub fn update(user_role: &UserRole, expected: EntityVersion) -> Self {
        Self {
            user_role: user_role.parts().clone(),
            expected: Some(expected),
        }
    }

    /// The state of the assignment to store.
    #[must_use]
    pub const fn user_role(&self) -> &UserRoleParts {
        &self.user_role
    }

    /// The version the stored assignment must hold; `None` for an insert.
    #[must_use]
    pub const fn expected(&self) -> Option<EntityVersion> {
        self.expected
    }
}

#[cfg(test)]
mod tests;
