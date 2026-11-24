//! The effective permissions of a subject (FR-39): every key or wildcard its active assignments
//! hold, with the roles that grant it, its scopes and the shortest expiry behind it.
//!
//! The composer reads the same data as the decision rule, the assignments and the compiled role
//! sets of one policy version, and applies the same two filters: an assignment grants only while
//! it is active, and a reserved `iam:` key counts only through a global assignment. The result is
//! computed when it is asked for (ADR 0020), so it can never disagree with a decision.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use crate::policy::decision_policy::{RoleAssignment, RoleSets, counts_for};
use crate::policy::wildcard_matcher::WildcardMatcher;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::{ProjectId, RoleId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::scope_set::ScopeSet;
use crate::value_object::service_name::ServiceName;

/// One key or wildcard that a subject holds, with what stands behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermission {
    grant: PermissionGrant,
    roles: BTreeSet<RoleId>,
    scopes: ScopeSet,
    expires_at: Option<SystemTime>,
}

impl EffectivePermission {
    /// The key or the wildcard pattern.
    #[must_use]
    pub const fn grant(&self) -> &PermissionGrant {
        &self.grant
    }

    /// The roles of the active assignments that grant it, in identifier order.
    #[must_use]
    pub const fn roles(&self) -> &BTreeSet<RoleId> {
        &self.roles
    }

    /// The projects it is held in: every project when a global assignment grants it.
    #[must_use]
    pub const fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }

    /// The shortest expiry among the contributing assignments that expire; `None` when none of
    /// them does.
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Whether this entry makes the subject hold `key`, whose catalogue flags are `flags`.
    ///
    /// It does when it is the key, a reserved key that covers it, or a wildcard that covers it
    /// (never a sensitive key).
    fn covers(&self, key: &PermissionKey, flags: PermissionFlags) -> bool {
        match &self.grant {
            PermissionGrant::Key(held) => held == key || reserved_covers(held, key),
            PermissionGrant::Wildcard(pattern) => WildcardMatcher::covers(pattern, key, flags),
        }
    }
}

/// Whether the reserved key `held` covers the reserved key `required`.
fn reserved_covers(held: &PermissionKey, required: &PermissionKey) -> bool {
    match (held, required) {
        (PermissionKey::Reserved(held), PermissionKey::Reserved(required)) => held.covers(required),
        _ => false,
    }
}

/// The read model of the effective permissions of a subject (board name `UserRolePermission`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePermission {
    policy_version: PolicyVersion,
    permissions: Vec<EffectivePermission>,
}

impl UserRolePermission {
    /// The policy version the permissions were composed at.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// The entries in grant order: exact keys first, then wildcard patterns.
    #[must_use]
    pub fn permissions(&self) -> &[EffectivePermission] {
        &self.permissions
    }

    /// The projects in which the subject holds `key` (catalogue flags `flags`).
    ///
    /// It is the union of the scopes of every entry that covers the key, empty when the subject does
    /// not hold it, and so the scope the decision rule allows the key in.
    #[must_use]
    pub fn scopes_of(&self, key: &PermissionKey, flags: PermissionFlags) -> ScopeSet {
        self.permissions
            .iter()
            .filter(|entry| entry.covers(key, flags))
            .fold(ScopeSet::empty(), |scopes, entry| {
                union(scopes, &entry.scopes)
            })
    }
}

/// The projects either set covers.
fn union(scopes: ScopeSet, other: &ScopeSet) -> ScopeSet {
    match (scopes, other) {
        (ScopeSet::All, _) | (_, ScopeSet::All) => ScopeSet::All,
        (ScopeSet::Projects(mut projects), ScopeSet::Projects(others)) => {
            projects.extend(others.iter().copied());
            ScopeSet::Projects(projects)
        }
    }
}

/// What narrows the read model: a project and a service, each optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectivePermissionFilter {
    /// Only assignments that apply in this project: the global ones and the ones of the project.
    pub project: Option<ProjectId>,
    /// Only keys and wildcards of this service.
    pub service: Option<ServiceName>,
}

impl EffectivePermissionFilter {
    fn admits_scope(&self, scope: AssignmentScope) -> bool {
        match (self.project, scope) {
            (None, _) | (Some(_), AssignmentScope::Global) => true,
            (Some(project), AssignmentScope::Project(own)) => project == own,
        }
    }

    fn admits_grant(&self, grant: &PermissionGrant) -> bool {
        self.service
            .as_ref()
            .is_none_or(|service| grant.service() == service)
    }
}

/// What the contributing assignments of one grant add up to.
#[derive(Debug, Default)]
struct Contribution {
    roles: BTreeSet<RoleId>,
    scopes: ScopeSet,
    expires_at: Option<SystemTime>,
}

impl Contribution {
    fn add(&mut self, assignment: &RoleAssignment) {
        self.roles.insert(assignment.role_id());
        self.scopes = std::mem::take(&mut self.scopes).with(assignment.scope());
        self.expires_at = match (self.expires_at, assignment.expires_at()) {
            (Some(held), Some(own)) => Some(held.min(own)),
            (held, own) => held.or(own),
        };
    }
}

/// Composes the effective permissions of a subject.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectivePermissionComposer;

impl EffectivePermissionComposer {
    /// Composes the read model at `policy_version`, narrowed by `filter`.
    ///
    /// The inputs are the subject's `assignments` (expired ones included: `now`, the time of the
    /// `Clock` port, drops them) and the compiled `role_sets` of the version.
    ///
    /// A role that the sets do not know contributes nothing, and a reserved key counts only
    /// through a global assignment, exactly as in [`DecisionPolicy`](super::decision_policy::DecisionPolicy).
    #[must_use]
    pub fn compose<R: RoleSets + ?Sized>(
        policy_version: PolicyVersion,
        assignments: &[RoleAssignment],
        role_sets: &R,
        filter: &EffectivePermissionFilter,
        now: SystemTime,
    ) -> UserRolePermission {
        let mut merged: BTreeMap<PermissionGrant, Contribution> = BTreeMap::new();
        for assignment in assignments
            .iter()
            .filter(|assignment| assignment.is_active_at(now))
            .filter(|assignment| filter.admits_scope(assignment.scope()))
        {
            let Some(set) = role_sets.role_set(assignment.role_id()) else {
                continue;
            };
            for grant in set.grants().filter(|grant| filter.admits_grant(grant)) {
                if holds_in(&grant, assignment.scope()) {
                    merged.entry(grant).or_default().add(assignment);
                }
            }
        }
        let permissions: Vec<EffectivePermission> = merged
            .into_iter()
            .map(|(grant, contribution)| EffectivePermission {
                grant,
                roles: contribution.roles,
                scopes: contribution.scopes,
                expires_at: contribution.expires_at,
            })
            .collect();
        UserRolePermission {
            policy_version,
            permissions,
        }
    }
}

/// Whether an assignment in `scope` makes the subject hold `grant`: a key of the service `iam`
/// only through a global assignment.
fn holds_in(grant: &PermissionGrant, scope: AssignmentScope) -> bool {
    match grant {
        PermissionGrant::Key(key) => counts_for(key, scope),
        PermissionGrant::Wildcard(_) => true,
    }
}

#[cfg(test)]
mod tests;
