//! The decision rule of FR-10, shared by `iam-control` and `iam-gateway`.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::time::SystemTime;

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::decision_outcome::DecisionVerdict;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::identifier::{ProjectId, RoleId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::scope_set::ScopeSet;

/// One assignment of a role to the subject, as the decision rule sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoleAssignment {
    role_id: RoleId,
    scope: AssignmentScope,
    expires_at: Option<SystemTime>,
}

impl RoleAssignment {
    /// An assignment of `role_id` in `scope` that expires at `expires_at`, or never.
    #[must_use]
    pub const fn new(
        role_id: RoleId,
        scope: AssignmentScope,
        expires_at: Option<SystemTime>,
    ) -> Self {
        Self {
            role_id,
            scope,
            expires_at,
        }
    }

    /// The assigned role.
    #[must_use]
    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    /// Where the assignment applies.
    #[must_use]
    pub const fn scope(&self) -> AssignmentScope {
        self.scope
    }

    /// When the assignment expires; `None` when it never does.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Whether the assignment grants its role at `now`: it expires at its expiry instant.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

/// One key a check requires, with its catalogue flags (most restrictive across active versions).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequiredKey {
    key: PermissionKey,
    flags: PermissionFlags,
}

impl RequiredKey {
    /// A required key with its flags.
    #[must_use]
    pub const fn new(key: PermissionKey, flags: PermissionFlags) -> Self {
        Self { key, flags }
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &PermissionKey {
        &self.key
    }

    /// The catalogue flags of the key.
    #[must_use]
    pub const fn flags(&self) -> PermissionFlags {
        self.flags
    }
}

/// The compiled role sets of one policy version, read from PostgreSQL or from the snapshot.
pub trait RoleSets {
    /// The compiled set of `role_id`; `None` for a role this version does not know.
    fn role_set(&self, role_id: RoleId) -> Option<&CompiledRoleSet>;
}

impl RoleSets for BTreeMap<RoleId, CompiledRoleSet> {
    fn role_set(&self, role_id: RoleId) -> Option<&CompiledRoleSet> {
        self.get(&role_id)
    }
}

impl<S: BuildHasher> RoleSets for HashMap<RoleId, CompiledRoleSet, S> {
    fn role_set(&self, role_id: RoleId) -> Option<&CompiledRoleSet> {
        self.get(&role_id)
    }
}

/// Everything one decision reads: the subject's assignments, the role sets of the policy
/// version, the required keys, the project of the check and the current time of the `Clock`.
#[derive(Debug)]
pub struct DecisionRequest<'input, R: RoleSets + ?Sized> {
    /// Every assignment of the subject, expired ones included.
    pub assignments: &'input [RoleAssignment],
    /// The compiled role sets of the policy version.
    pub role_sets: &'input R,
    /// The keys the check requires.
    pub required: &'input [RequiredKey],
    /// The project of the check.
    pub project: Option<ProjectId>,
    /// The current time, from the `Clock` port.
    pub now: SystemTime,
}

/// A required key and the projects in which the subject holds it.
type HeldKey<'input> = (&'input RequiredKey, ScopeSet);

/// The decision rule: a check is allowed only when every required key is held by an active
/// assignment in the requested scope (FR-10).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionPolicy;

impl DecisionPolicy {
    /// Decides one check.
    ///
    /// A key nobody holds denies with `permission_missing`; keys held only in other projects deny
    /// with `scope_missing`. Without a project the check is allowed in the projects where every
    /// key is held, listed in the scopes. A check that requires no key is `malformed_operation`.
    /// A reserved `iam:` key counts only through a global assignment, so a project assignment
    /// never lends it to a check with or without a project.
    #[must_use]
    pub fn decide<R: RoleSets + ?Sized>(request: &DecisionRequest<'_, R>) -> DecisionVerdict {
        if request.required.is_empty() {
            return DecisionVerdict::deny(DecisionReason::MalformedOperation, Vec::new());
        }
        let held: Vec<HeldKey<'_>> = request
            .required
            .iter()
            .map(|required| (required, Self::scope_of(request, required)))
            .collect();
        let missing = denied_where(&held, ScopeSet::is_empty);
        if !missing.is_empty() {
            return DecisionVerdict::deny(DecisionReason::PermissionMissing, missing);
        }
        Self::decide_scope(&held, request.project)
    }

    /// The projects in which the subject's active assignments hold the key; a reserved key is
    /// held only through global assignments.
    fn scope_of<R: RoleSets + ?Sized>(
        request: &DecisionRequest<'_, R>,
        required: &RequiredKey,
    ) -> ScopeSet {
        request
            .assignments
            .iter()
            .filter(|assignment| assignment.is_active_at(request.now))
            .filter(|assignment| counts_for(required.key(), assignment.scope()))
            .filter(|assignment| {
                request
                    .role_sets
                    .role_set(assignment.role_id())
                    .is_some_and(|set| set.holds(required.key(), required.flags()))
            })
            .fold(ScopeSet::empty(), |scopes, assignment| {
                scopes.with(assignment.scope())
            })
    }

    /// Decides keys that are all held somewhere against the project of the check.
    fn decide_scope(held: &[HeldKey<'_>], project: Option<ProjectId>) -> DecisionVerdict {
        let common = held.iter().fold(ScopeSet::All, |common, (_, scopes)| {
            common.intersect(scopes)
        });
        match project {
            Some(project_id) if !common.covers(project_id) => DecisionVerdict::deny(
                DecisionReason::ScopeMissing,
                denied_where(held, |scopes| !scopes.covers(project_id)),
            ),
            None if common.is_empty() => DecisionVerdict::deny(
                DecisionReason::ScopeMissing,
                denied_where(held, |scopes| !scopes.is_all()),
            ),
            Some(_) | None => DecisionVerdict::allow(common),
        }
    }
}

/// Whether an assignment in `scope` can hold `key`: reserved `iam:` keys administer IAM itself
/// and are required at global scope (FR-4, FR-12, FR-25), so only a global assignment holds them;
/// every other key is held in the scope of its assignment.
const fn counts_for(key: &PermissionKey, scope: AssignmentScope) -> bool {
    !matches!(key, PermissionKey::Reserved(_)) || matches!(scope, AssignmentScope::Global)
}

/// The text of every held key whose scopes match `denied`, in required order.
fn denied_where(held: &[HeldKey<'_>], denied: impl Fn(&ScopeSet) -> bool) -> Vec<String> {
    held.iter()
        .filter(|(_, scopes)| denied(scopes))
        .map(|(required, _)| required.key().to_string())
        .collect()
}

#[cfg(test)]
mod tests;
