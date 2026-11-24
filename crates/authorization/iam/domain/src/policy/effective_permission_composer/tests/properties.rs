//! Property test: the read model holds a key exactly where the decision rule allows it.
//!
//! Failures replay from `PROPTEST_RNG_SEED`.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::{Strategy, any};

use super::{NOW, at, compose, project, role};
use crate::policy::compiled_role_set::{CompiledRoleSet, GrantStatus};
use crate::policy::decision_policy::{
    DecisionPolicy, DecisionRequest, RequiredKey, RoleAssignment,
};
use crate::policy::effective_permission_composer::EffectivePermissionFilter;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::scope_set::ScopeSet;

/// The keys of the random catalogue with their sensitive flag.
const KEYS: [(&str, bool); 8] = [
    ("rest:orders:GET /api/orders", false),
    ("rest:orders:POST /api/orders", true),
    ("gql:orders:Query.order", false),
    ("gql:orders:Mutation.cancelOrder", true),
    ("gql:orders:__introspection", false),
    ("rest:billing:GET /api/invoices", false),
    ("iam:audit:read", false),
    ("iam:validate:orders", false),
];

/// Every grant a random role may hold.
const GRANTS: [&str; 14] = [
    "rest:orders:GET /api/orders",
    "rest:orders:POST /api/orders",
    "gql:orders:Query.order",
    "gql:orders:Mutation.cancelOrder",
    "gql:orders:__introspection",
    "rest:billing:GET /api/invoices",
    "iam:audit:read",
    "iam:validate:*",
    "rest:orders:*",
    "rest:orders:GET *",
    "gql:orders:Query.*",
    "gql:orders:*",
    "rest:billing:*",
    "iam:validate:orders",
];

const ROLES: u8 = 3;

/// A random assignment: role, scope (0 global, else the project) and expiry (0 never, 1 passed,
/// 2 at now, 3 later).
#[derive(Debug, Clone, Copy)]
struct Assign {
    role: u8,
    scope: u8,
    expiry: u8,
}

#[derive(Debug, Clone)]
struct Policy {
    roles: Vec<Vec<(usize, bool)>>,
    assignments: Vec<Assign>,
}

fn policy_strategy() -> impl Strategy<Value = Policy> {
    let assign = (0..ROLES, 0..=2_u8, 0..4_u8).prop_map(|(role, scope, expiry)| Assign {
        role,
        scope,
        expiry,
    });
    (
        vec(
            vec((0..GRANTS.len(), any::<bool>()), 0..6),
            usize::from(ROLES),
        ),
        vec(assign, 0..6),
    )
        .prop_map(|(roles, assignments)| Policy { roles, assignments })
}

fn compiled(policy: &Policy) -> BTreeMap<RoleId, CompiledRoleSet> {
    policy
        .roles
        .iter()
        .enumerate()
        .map(|(index, grants)| {
            let grants = grants.iter().map(|(grant, orphaned)| {
                let status = if *orphaned {
                    GrantStatus::Orphaned
                } else {
                    GrantStatus::Active
                };
                let text = GRANTS.get(*grant).copied().unwrap();
                (PermissionGrant::parse(text).unwrap(), status)
            });
            let number = u8::try_from(index).unwrap();
            (role(number), CompiledRoleSet::compile(grants))
        })
        .collect()
}

fn assignments(policy: &Policy) -> Vec<RoleAssignment> {
    policy
        .assignments
        .iter()
        .map(|assign| {
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
        })
        .collect()
}

proptest::proptest! {
    #[test]
    fn the_read_model_holds_exactly_the_keys_the_decision_rule_allows(policy in policy_strategy()) {
        let sets = compiled(&policy);
        let held = assignments(&policy);
        let read_model = compose(&held, &sets, &EffectivePermissionFilter::default());

        for (text, is_sensitive) in KEYS {
            let flags = if is_sensitive {
                PermissionFlags::NONE.with_sensitive()
            } else {
                PermissionFlags::NONE
            };
            let parsed = PermissionKey::parse(text).unwrap();
            let verdict = DecisionPolicy::decide(&DecisionRequest {
                assignments: &held,
                role_sets: &sets,
                required: &[RequiredKey::new(parsed.clone(), flags)],
                project: None,
                now: at(NOW),
            });
            let scopes = read_model.scopes_of(&parsed, flags);

            proptest::prop_assert_eq!(
                verdict.decision().is_allow(),
                !scopes.is_empty(),
                "key set differs for {}", text
            );
            if verdict.decision().is_allow() {
                proptest::prop_assert_eq!(verdict.scopes(), &scopes);
            } else {
                proptest::prop_assert_eq!(scopes, ScopeSet::empty());
            }
        }
    }
}
