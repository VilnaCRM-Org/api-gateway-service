//! The policy data one decision reads about a subject: its assignments and their role sets,
//! stamped with the policy version of the snapshot they were read in.

use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::{
    DecisionPolicy, DecisionRequest, RequiredKey, RoleAssignment,
};
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::reserved_permission::ReservedPermission;

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

    /// Whether an active global assignment of the subject holds the reserved `key` at `now`: a
    /// reserved key held only through a project assignment does not count, and `iam:grant:*`
    /// holds every `iam:grant:{service}`, which the decision rule decides.
    #[must_use]
    pub fn holds_reserved(&self, key: &ReservedPermission, now: SystemTime) -> bool {
        let required = [RequiredKey::new(
            PermissionKey::Reserved(key.clone()),
            PermissionFlags::NONE,
        )];
        DecisionPolicy::decide(&DecisionRequest {
            assignments: &self.assignments,
            role_sets: &self.role_sets,
            required: &required,
            project: None,
            now,
        })
        .decision()
        .is_allow()
    }
}

#[cfg(test)]
mod tests;
