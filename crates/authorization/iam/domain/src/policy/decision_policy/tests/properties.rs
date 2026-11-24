//! Property tests of the decision rule over random policies: monotonicity in the grants, and
//! agreement with an independent reference rule (zero false allows, zero false denies).
//!
//! Failures replay from `PROPTEST_RNG_SEED`.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::{Strategy, any, prop};

use super::{NOW, at, decide, project, projects, role};
use crate::policy::compiled_role_set::{CompiledRoleSet, GrantStatus};
use crate::policy::decision_policy::{RequiredKey, RoleAssignment};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::decision_outcome::DecisionVerdict;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::scope_set::ScopeSet;

/// The keys of the random catalogue with their sensitive flag.
const KEYS: [(&str, bool); 9] = [
    ("rest:orders:GET /api/orders", false),
    ("rest:orders:POST /api/orders", true),
    ("gql:orders:Query.order", false),
    ("gql:orders:Mutation.cancelOrder", true),
    ("gql:orders:__introspection", false),
    ("rest:billing:GET /api/invoices", false),
    ("iam:audit:read", false),
    ("rest:iam:POST /api/roles", false),
    ("gql:iam:Mutation.createRole", false),
];

/// Every grant a random role may hold: each key and wildcard patterns.
const GRANTS: [&str; 16] = [
    "rest:orders:GET /api/orders",
    "rest:orders:POST /api/orders",
    "gql:orders:Query.order",
    "gql:orders:Mutation.cancelOrder",
    "gql:orders:__introspection",
    "rest:billing:GET /api/invoices",
    "iam:audit:read",
    "rest:iam:POST /api/roles",
    "gql:iam:Mutation.createRole",
    "rest:iam:*",
    "gql:iam:*",
    "rest:orders:*",
    "rest:orders:GET *",
    "gql:orders:Query.*",
    "gql:orders:*",
    "rest:billing:*",
];

/// The projects assignments may name; a check may also name project 3, which none names.
const PROJECTS: [u8; 2] = [1, 2];
const ROLES: u8 = 3;

/// A random grant: index into [`GRANTS`] and whether it is orphaned.
type Grant = (usize, bool);

/// A random assignment: role, scope (0 global, else the project) and expiry (0 never,
/// 1 passed, 2 at now, 3 later).
#[derive(Debug, Clone, Copy)]
struct Assign {
    role: u8,
    scope: u8,
    expiry: u8,
}

#[derive(Debug, Clone)]
struct Policy {
    roles: Vec<Vec<Grant>>,
    assignments: Vec<Assign>,
    keys: Vec<usize>,
    project: Option<u8>,
}

fn grant_strategy() -> impl Strategy<Value = Grant> {
    (0..GRANTS.len(), any::<bool>())
}

fn policy_strategy() -> impl Strategy<Value = Policy> {
    let assign = (0..ROLES, 0..=2_u8, 0..4_u8).prop_map(|(role, scope, expiry)| Assign {
        role,
        scope,
        expiry,
    });
    (
        vec(vec(grant_strategy(), 0..6), usize::from(ROLES)),
        vec(assign, 0..6),
        vec(0..KEYS.len(), 1..4),
        prop::option::of(1..=3_u8),
    )
        .prop_map(|(roles, assignments, keys, project)| Policy {
            roles,
            assignments,
            keys,
            project,
        })
}

fn grant_text(grant: Grant) -> &'static str {
    GRANTS.get(grant.0).copied().unwrap()
}

fn key_entry(index: usize) -> (&'static str, bool) {
    KEYS.get(index).copied().unwrap()
}

fn role_number(index: usize) -> u8 {
    u8::try_from(index).unwrap()
}

fn compiled(policy: &Policy) -> BTreeMap<RoleId, CompiledRoleSet> {
    policy
        .roles
        .iter()
        .enumerate()
        .map(|(index, grants)| {
            let grants = grants.iter().map(|grant| {
                let status = if grant.1 {
                    GrantStatus::Orphaned
                } else {
                    GrantStatus::Active
                };
                (PermissionGrant::parse(grant_text(*grant)).unwrap(), status)
            });
            (role(role_number(index)), CompiledRoleSet::compile(grants))
        })
        .collect()
}

fn assignment(assign: Assign) -> RoleAssignment {
    let scope = if assign.scope == 0 {
        AssignmentScope::Global
    } else {
        AssignmentScope::Project(project(assign.scope))
    };
    let expires_at = match assign.expiry {
        0 => None,
        1 => Some(at(NOW - 1)),
        2 => Some(at(NOW)),
        _ => Some(at(NOW + 1)),
    };
    RoleAssignment::new(role(assign.role), scope, expires_at)
}

fn verdict(policy: &Policy) -> DecisionVerdict {
    let assignments: Vec<RoleAssignment> =
        policy.assignments.iter().copied().map(assignment).collect();
    let keys: Vec<RequiredKey> = policy
        .keys
        .iter()
        .map(|index| {
            let (text, is_sensitive) = key_entry(*index);
            let flags = if is_sensitive {
                PermissionFlags::NONE.with_sensitive()
            } else {
                PermissionFlags::NONE
            };
            RequiredKey::new(PermissionKey::parse(text).unwrap(), flags)
        })
        .collect();
    decide(
        &assignments,
        &compiled(policy),
        &keys,
        policy.project.map(project),
    )
}

/// The reference reading of FR-10, written on the key text: a grant covers a key when it is the
/// key, or when it ends in `*`, the key is neither sensitive nor reserved and starts with the
/// grant's text before the `*`.
fn reference_covers(grant: &str, key: &str, is_sensitive: bool) -> bool {
    if grant == key {
        return true;
    }
    if is_sensitive || key.starts_with("iam:") {
        return false;
    }
    grant
        .strip_suffix('*')
        .is_some_and(|prefix| key.starts_with(prefix))
}

/// Whether the key belongs to the service `iam`: a reserved key or a catalogue key of `iam`.
fn is_iam_key(key: &str) -> bool {
    key.starts_with("iam:") || key.starts_with("rest:iam:") || key.starts_with("gql:iam:")
}

/// Whether the reference holds the key through an active assignment whose scope is `scope`; a
/// key of the service `iam` is held only through a global assignment.
fn reference_holds(policy: &Policy, key_index: usize, scope: u8) -> bool {
    let (key, is_sensitive) = key_entry(key_index);
    if scope != 0 && is_iam_key(key) {
        return false;
    }
    policy
        .assignments
        .iter()
        .filter(|assign| assign.expiry == 0 || assign.expiry == 3)
        .filter(|assign| assign.scope == scope)
        .filter_map(|assign| policy.roles.get(usize::from(assign.role)))
        .flatten()
        .any(|grant| !grant.1 && reference_covers(grant_text(*grant), key, is_sensitive))
}

/// Whether the reference holds the key in project `number` (globally or there).
fn reference_holds_in(policy: &Policy, key_index: usize, number: u8) -> bool {
    reference_holds(policy, key_index, 0) || reference_holds(policy, key_index, number)
}

fn reference_held_anywhere(policy: &Policy, key_index: usize) -> bool {
    reference_holds(policy, key_index, 0)
        || PROJECTS
            .iter()
            .any(|number| reference_holds(policy, key_index, *number))
}

fn reference_scopes(policy: &Policy) -> ScopeSet {
    if policy
        .keys
        .iter()
        .all(|key| reference_holds(policy, *key, 0))
    {
        return ScopeSet::All;
    }
    let common: Vec<u8> = PROJECTS
        .iter()
        .copied()
        .filter(|number| {
            policy
                .keys
                .iter()
                .all(|key| reference_holds_in(policy, *key, *number))
        })
        .collect();
    projects(&common)
}

fn key_texts(policy: &Policy, denied: impl Fn(usize) -> bool) -> Vec<String> {
    policy
        .keys
        .iter()
        .copied()
        .filter(|key| denied(*key))
        .map(|key| key_entry(key).0.to_owned())
        .collect()
}

fn reference_verdict(policy: &Policy) -> DecisionVerdict {
    let missing = key_texts(policy, |key| !reference_held_anywhere(policy, key));
    if !missing.is_empty() {
        return DecisionVerdict::deny(DecisionReason::PermissionMissing, missing);
    }
    let scopes = reference_scopes(policy);
    match policy.project {
        Some(number) if !scopes.covers(project(number)) => DecisionVerdict::deny(
            DecisionReason::ScopeMissing,
            key_texts(policy, |key| !reference_holds_in(policy, key, number)),
        ),
        None if scopes.is_empty() => DecisionVerdict::deny(
            DecisionReason::ScopeMissing,
            key_texts(policy, |key| !reference_holds(policy, key, 0)),
        ),
        Some(_) | None => DecisionVerdict::allow(scopes),
    }
}

fn with_grant(policy: &Policy, role_index: usize, grant: usize) -> Policy {
    let mut changed = policy.clone();
    if let Some(grants) = changed.roles.get_mut(role_index) {
        grants.push((grant, false));
    }
    changed
}

fn without_grant(policy: &Policy, role_index: usize, position: usize) -> Policy {
    let mut changed = policy.clone();
    if let Some(grants) = changed.roles.get_mut(role_index)
        && !grants.is_empty()
    {
        grants.remove(position.checked_rem(grants.len()).unwrap());
    }
    changed
}

proptest::proptest! {
    #[test]
    fn the_rule_agrees_with_the_reference_with_no_false_allow_or_deny(policy in policy_strategy()) {
        let actual = verdict(&policy);
        let expected = reference_verdict(&policy);

        proptest::prop_assert_eq!(actual.decision(), expected.decision(), "false allow or deny");
        proptest::prop_assert_eq!(actual, expected);
    }

    #[test]
    fn adding_a_grant_never_turns_an_allow_into_a_deny(
        policy in policy_strategy(),
        role_index in 0..usize::from(ROLES),
        grant in 0..GRANTS.len(),
    ) {
        let before = verdict(&policy);
        let after = verdict(&with_grant(&policy, role_index, grant));

        proptest::prop_assert!(!before.decision().is_allow() || after.decision().is_allow());
    }

    #[test]
    fn removing_a_grant_never_turns_a_deny_into_an_allow(
        policy in policy_strategy(),
        role_index in 0..usize::from(ROLES),
        position in any::<usize>(),
    ) {
        let before = verdict(&policy);
        let after = verdict(&without_grant(&policy, role_index, position));

        proptest::prop_assert!(before.decision().is_allow() || !after.decision().is_allow());
    }
}
