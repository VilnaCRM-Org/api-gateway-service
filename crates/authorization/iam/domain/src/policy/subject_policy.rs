//! The policy data one decision reads about a subject: its assignments and their role sets,
//! stamped with the policy version of the snapshot they were read in.

use std::collections::BTreeMap;

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::RoleAssignment;
use crate::value_object::identifier::RoleId;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;

/// The policy data of a subject.
///
/// It holds the assignments, expired ones included so that the `Clock` port decides, the compiled
/// sets of the roles they name (active grants only) and the policy epoch, all read in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPolicy {
    epoch: PolicyEpoch,
    assignments: Vec<RoleAssignment>,
    role_sets: BTreeMap<RoleId, CompiledRoleSet>,
}

impl SubjectPolicy {
    /// The policy data of a subject, read at `epoch`.
    #[must_use]
    pub const fn new(
        epoch: PolicyEpoch,
        assignments: Vec<RoleAssignment>,
        role_sets: BTreeMap<RoleId, CompiledRoleSet>,
    ) -> Self {
        Self {
            epoch,
            assignments,
            role_sets,
        }
    }

    /// The policy epoch of the snapshot.
    #[must_use]
    pub const fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    /// The policy version of the snapshot.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.epoch.version()
    }

    /// Every assignment of the subject that is not revoked, expired ones included.
    #[must_use]
    pub fn assignments(&self) -> &[RoleAssignment] {
        &self.assignments
    }

    /// The compiled sets of the roles the assignments name; a role that no longer exists has none.
    #[must_use]
    pub const fn role_sets(&self) -> &BTreeMap<RoleId, CompiledRoleSet> {
        &self.role_sets
    }
}

#[cfg(test)]
mod tests;
