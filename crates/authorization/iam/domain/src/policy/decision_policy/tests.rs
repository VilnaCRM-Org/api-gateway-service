mod corpus;
mod properties;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, SystemTime};

use rstest::rstest;

use super::{DecisionPolicy, DecisionRequest, RequiredKey, RoleAssignment, RoleSets};
use crate::policy::compiled_role_set::{CompiledRoleSet, GrantStatus};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::decision::Decision;
use crate::value_object::decision_outcome::DecisionVerdict;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::identifier::{ProjectId, RoleId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::scope_set::ScopeSet;

const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn role(number: u8) -> RoleId {
    RoleId::parse(&format!("00000000-0000-7000-8000-0000000001{number:02x}")).unwrap()
}

fn project(number: u8) -> ProjectId {
    ProjectId::parse(&format!("00000000-0000-7000-8000-0000000002{number:02x}")).unwrap()
}

fn required(text: &str) -> RequiredKey {
    RequiredKey::new(PermissionKey::parse(text).unwrap(), PermissionFlags::NONE)
}

fn sensitive(text: &str) -> RequiredKey {
    RequiredKey::new(
        PermissionKey::parse(text).unwrap(),
        PermissionFlags::NONE.with_sensitive(),
    )
}

/// One role of a test: `(role, active grants, orphaned grants)`.
type RoleSpec<'a> = (u8, &'a [&'a str], &'a [&'a str]);

/// Compiles roles from `(role, active grants, orphaned grants)`.
fn role_sets(roles: &[RoleSpec<'_>]) -> BTreeMap<RoleId, CompiledRoleSet> {
    roles
        .iter()
        .map(|(number, active, orphaned)| {
            let grants =
                active
                    .iter()
                    .map(|text| (PermissionGrant::parse(text).unwrap(), GrantStatus::Active))
                    .chain(orphaned.iter().map(|text| {
                        (PermissionGrant::parse(text).unwrap(), GrantStatus::Orphaned)
                    }));
            (role(*number), CompiledRoleSet::compile(grants))
        })
        .collect()
}

fn global(role_number: u8) -> RoleAssignment {
    RoleAssignment::new(role(role_number), AssignmentScope::Global, None)
}

fn in_project(role_number: u8, project_number: u8) -> RoleAssignment {
    RoleAssignment::new(
        role(role_number),
        AssignmentScope::Project(project(project_number)),
        None,
    )
}

fn decide<R: RoleSets + ?Sized>(
    assignments: &[RoleAssignment],
    roles: &R,
    keys: &[RequiredKey],
    project: Option<ProjectId>,
) -> DecisionVerdict {
    DecisionPolicy::decide(&DecisionRequest {
        assignments,
        role_sets: roles,
        required: keys,
        project,
        now: at(NOW),
    })
}

fn projects(numbers: &[u8]) -> ScopeSet {
    ScopeSet::Projects(
        numbers
            .iter()
            .copied()
            .map(project)
            .collect::<BTreeSet<_>>(),
    )
}

#[rstest]
#[case::exact("rest:orders:GET /api/orders/{}")]
#[case::method_wildcard("rest:orders:GET *")]
#[case::service_wildcard("rest:orders:*")]
fn a_key_held_exactly_or_through_a_covering_wildcard_globally_is_allowed_everywhere(
    #[case] grant: &str,
) {
    let roles = role_sets(&[(1, &[grant], &[])]);
    let keys = [required("rest:orders:GET /api/orders/{}")];

    for project_number in [None, Some(project(1))] {
        let verdict = decide(&[global(1)], &roles, &keys, project_number);

        assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
    }
}

#[rstest]
#[case("gql:orders:Query.*", "gql:orders:Query.order")]
#[case("gql:orders:*", "gql:orders:Mutation.cancelOrder")]
#[case("gql:orders:*", "gql:orders:__introspection")]
fn a_graphql_wildcard_allows_the_coordinates_it_covers(#[case] grant: &str, #[case] key: &str) {
    let roles = role_sets(&[(1, &[grant], &[])]);

    let verdict = decide(&[global(1)], &roles, &[required(key)], None);

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
}

#[rstest]
#[case("rest:orders:*", "rest:orders:POST /api/orders")]
#[case("rest:orders:POST *", "rest:orders:POST /api/orders")]
#[case("gql:orders:*", "gql:orders:Mutation.cancelOrder")]
#[case("gql:orders:Mutation.*", "gql:orders:Mutation.cancelOrder")]
fn a_wildcard_never_grants_a_sensitive_key(#[case] grant: &str, #[case] key: &str) {
    let roles = role_sets(&[(1, &[grant], &[])]);

    let verdict = decide(&[global(1)], &roles, &[sensitive(key)], None);

    assert_eq!(
        verdict,
        DecisionVerdict::deny(DecisionReason::PermissionMissing, vec![key.to_owned()])
    );
}

#[test]
fn an_exact_grant_of_a_sensitive_key_is_allowed() {
    let roles = role_sets(&[(1, &["rest:orders:POST /api/orders"], &[])]);

    let verdict = decide(
        &[global(1)],
        &roles,
        &[sensitive("rest:orders:POST /api/orders")],
        None,
    );

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
}

#[test]
fn project_assignments_allow_the_matching_project_only() {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);
    let keys = [required("gql:orders:Query.order")];
    let assignments = [in_project(1, 1), in_project(1, 2)];

    let matching = decide(&assignments, &roles, &keys, Some(project(1)));
    let other = decide(&assignments, &roles, &keys, Some(project(3)));
    let absent = decide(&assignments, &roles, &keys, None);

    assert_eq!(matching.decision(), Decision::Allow);
    assert_eq!(matching.scopes(), &projects(&[1, 2]));
    assert_eq!(
        other,
        DecisionVerdict::deny(
            DecisionReason::ScopeMissing,
            vec![String::from("gql:orders:Query.order")]
        )
    );
    assert_eq!(absent, DecisionVerdict::allow(projects(&[1, 2])));
}

#[test]
fn a_global_assignment_beside_project_ones_reports_all() {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);

    let verdict = decide(
        &[in_project(1, 1), global(1)],
        &roles,
        &[required("gql:orders:Query.order")],
        Some(project(9)),
    );

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
}

#[rstest]
#[case::expired_before(NOW - 1)]
#[case::expiring_now(NOW)]
fn an_expired_assignment_contributes_nothing(#[case] expires_at: u64) {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);
    let expired = RoleAssignment::new(role(1), AssignmentScope::Global, Some(at(expires_at)));

    let verdict = decide(
        &[expired],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::PermissionMissing,
            vec![String::from("gql:orders:Query.order")]
        )
    );
}

#[test]
fn an_assignment_that_expires_later_still_grants() {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);
    let later = RoleAssignment::new(role(1), AssignmentScope::Global, Some(at(NOW + 1)));

    let verdict = decide(
        &[later],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
}

#[test]
fn an_orphaned_grant_contributes_nothing() {
    let roles = role_sets(&[(1, &[], &["gql:orders:Query.order", "gql:orders:*"])]);

    let verdict = decide(
        &[global(1)],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::PermissionMissing,
            vec![String::from("gql:orders:Query.order")]
        )
    );
}

#[test]
fn another_grant_still_holds_the_key_beside_an_expired_or_orphaned_one() {
    let roles = role_sets(&[
        (1, &["gql:orders:Query.order"], &[]),
        (2, &[], &["gql:orders:Query.order"]),
        (3, &["gql:orders:Query.*"], &[]),
    ]);
    let expired = RoleAssignment::new(role(1), AssignmentScope::Global, Some(at(NOW - 5)));

    let verdict = decide(
        &[expired, global(2), in_project(3, 4)],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(verdict, DecisionVerdict::allow(projects(&[4])));
}

#[test]
fn an_unknown_role_contributes_nothing() {
    let roles = role_sets(&[]);

    let verdict = decide(
        &[global(1)],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(verdict.reason(), DecisionReason::PermissionMissing);
}

#[test]
fn a_subject_without_assignments_is_denied_with_every_key_listed() {
    let roles = role_sets(&[(1, &["gql:orders:*"], &[])]);
    let keys = [
        required("gql:orders:Query.order"),
        required("gql:orders:Query.orders"),
    ];

    let verdict = decide(&[], &roles, &keys, None);

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::PermissionMissing,
            vec![
                String::from("gql:orders:Query.order"),
                String::from("gql:orders:Query.orders")
            ]
        )
    );
}

#[test]
fn a_check_is_all_or_nothing_and_lists_only_the_missing_keys() {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);
    let keys = [
        required("gql:orders:Query.order"),
        required("gql:orders:Mutation.cancelOrder"),
    ];

    let verdict = decide(&[global(1)], &roles, &keys, None);

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::PermissionMissing,
            vec![String::from("gql:orders:Mutation.cancelOrder")]
        )
    );
}

#[test]
fn permission_missing_wins_over_scope_missing() {
    let roles = role_sets(&[(1, &["gql:orders:Query.order"], &[])]);
    let keys = [
        required("gql:orders:Query.order"),
        required("gql:orders:Query.orders"),
    ];

    let verdict = decide(&[in_project(1, 1)], &roles, &keys, Some(project(2)));

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::PermissionMissing,
            vec![String::from("gql:orders:Query.orders")]
        )
    );
}

#[test]
fn keys_held_in_different_projects_only_are_denied_without_a_project() {
    let roles = role_sets(&[
        (1, &["gql:orders:Query.order"], &[]),
        (2, &["gql:orders:Query.orders"], &[]),
        (3, &["gql:orders:Query.customer"], &[]),
    ]);
    let keys = [
        required("gql:orders:Query.order"),
        required("gql:orders:Query.orders"),
        required("gql:orders:Query.customer"),
    ];

    let verdict = decide(
        &[in_project(1, 1), in_project(2, 2), global(3)],
        &roles,
        &keys,
        None,
    );

    assert_eq!(
        verdict,
        DecisionVerdict::deny(
            DecisionReason::ScopeMissing,
            vec![
                String::from("gql:orders:Query.order"),
                String::from("gql:orders:Query.orders")
            ]
        )
    );
}

#[test]
fn several_keys_are_allowed_in_the_projects_where_every_key_is_held() {
    let roles = role_sets(&[
        (1, &["gql:orders:Query.order"], &[]),
        (2, &["gql:orders:Query.orders"], &[]),
    ]);
    let keys = [
        required("gql:orders:Query.order"),
        required("gql:orders:Query.orders"),
    ];
    let assignments = [
        in_project(1, 1),
        in_project(1, 2),
        in_project(2, 2),
        global(2),
    ];

    let absent = decide(&assignments, &roles, &keys, None);
    let other = decide(&assignments, &roles, &keys, Some(project(3)));

    assert_eq!(absent, DecisionVerdict::allow(projects(&[1, 2])));
    assert_eq!(
        other,
        DecisionVerdict::deny(
            DecisionReason::ScopeMissing,
            vec![String::from("gql:orders:Query.order")]
        )
    );
}

#[test]
fn a_check_that_requires_no_key_is_malformed() {
    let roles = role_sets(&[(1, &["gql:orders:*"], &[])]);

    let verdict = decide(&[global(1)], &roles, &[], None);

    assert_eq!(
        verdict,
        DecisionVerdict::deny(DecisionReason::MalformedOperation, Vec::new())
    );
}

#[test]
fn a_reserved_key_is_held_through_its_covering_reserved_key() {
    let roles = role_sets(&[(1, &["iam:validate:*"], &[])]);

    let allowed = decide(
        &[global(1)],
        &roles,
        &[required("iam:validate:orders")],
        None,
    );
    let denied = decide(&[global(1)], &roles, &[required("iam:grant:orders")], None);

    assert_eq!(allowed, DecisionVerdict::allow(ScopeSet::All));
    assert_eq!(denied.reason(), DecisionReason::PermissionMissing);
}

#[test]
fn a_project_assignment_never_holds_a_reserved_key() {
    let roles = role_sets(&[(1, &["iam:grant:*"], &[])]);
    let keys = [required("iam:grant:orders")];

    let without_project = decide(&[in_project(1, 1)], &roles, &keys, None);
    let in_its_project = decide(&[in_project(1, 1)], &roles, &keys, Some(project(1)));

    let missing = DecisionVerdict::deny(
        DecisionReason::PermissionMissing,
        vec!["iam:grant:orders".to_owned()],
    );
    assert_eq!(without_project, missing);
    assert_eq!(in_its_project, missing);
}

#[test]
fn a_global_assignment_holds_a_reserved_key_beside_a_project_one() {
    let roles = role_sets(&[(1, &["iam:grant:*"], &[])]);

    let verdict = decide(
        &[in_project(1, 1), global(1)],
        &roles,
        &[required("iam:grant:orders")],
        Some(project(2)),
    );

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
}

#[test]
fn role_sets_may_live_in_a_hash_map() {
    let roles: HashMap<RoleId, CompiledRoleSet> =
        role_sets(&[(1, &["gql:orders:Query.order"], &[])])
            .into_iter()
            .collect();

    let verdict = decide(
        &[global(1)],
        &roles,
        &[required("gql:orders:Query.order")],
        None,
    );

    assert_eq!(verdict, DecisionVerdict::allow(ScopeSet::All));
    assert!(roles.role_set(role(2)).is_none());
}

#[test]
fn an_assignment_exposes_its_parts() {
    let expires_at = at(NOW + 60);
    let assignment = RoleAssignment::new(
        role(1),
        AssignmentScope::Project(project(1)),
        Some(expires_at),
    );

    assert_eq!(assignment.role_id(), role(1));
    assert_eq!(assignment.scope(), AssignmentScope::Project(project(1)));
    assert_eq!(assignment.expires_at(), Some(expires_at));
    assert!(assignment.is_active_at(at(NOW + 59)));
    assert!(!assignment.is_active_at(at(NOW + 60)));
    assert!(global(1).is_active_at(at(u64::from(u32::MAX))));
}

#[test]
fn a_required_key_exposes_its_key_and_flags() {
    let key = sensitive("rest:orders:POST /api/orders");

    assert_eq!(
        key.key(),
        &PermissionKey::parse("rest:orders:POST /api/orders").unwrap()
    );
    assert!(key.flags().is_sensitive());
}

fn through_wildcard(
    assignments: &[RoleAssignment],
    roles: &BTreeMap<RoleId, CompiledRoleSet>,
    keys: &[RequiredKey],
) -> bool {
    DecisionPolicy::holds_through_wildcard(&DecisionRequest {
        assignments,
        role_sets: roles,
        required: keys,
        project: None,
        now: at(NOW),
    })
}

#[rstest]
#[case::method_wildcard("rest:orders:GET *", true)]
#[case::service_wildcard("rest:orders:*", true)]
#[case::exact("rest:orders:GET /api/orders/{}", false)]
fn a_key_held_through_a_wildcard_is_a_wildcard_allow_and_one_held_exactly_is_not(
    #[case] grant: &str,
    #[case] expected: bool,
) {
    let roles = role_sets(&[(1, &[grant], &[])]);
    let keys = [required("rest:orders:GET /api/orders/{}")];

    assert_eq!(through_wildcard(&[global(1)], &roles, &keys), expected);
}

#[test]
fn a_key_that_another_role_holds_exactly_is_not_a_wildcard_allow() {
    let roles = role_sets(&[
        (1, &["rest:orders:*"], &[]),
        (2, &["rest:orders:GET /api/orders/{}"], &[]),
    ]);
    let keys = [required("rest:orders:GET /api/orders/{}")];

    assert!(!through_wildcard(&[global(1), global(2)], &roles, &keys));
    assert!(through_wildcard(&[global(1)], &roles, &keys));
}

#[test]
fn an_expired_or_unknown_assignment_makes_no_wildcard_allow() {
    let roles = role_sets(&[(1, &["rest:orders:*"], &[])]);
    let keys = [required("rest:orders:GET /api/orders/{}")];
    let expired = RoleAssignment::new(role(1), AssignmentScope::Global, Some(at(NOW)));

    assert!(!through_wildcard(&[expired], &roles, &keys));
    assert!(!through_wildcard(&[global(9)], &roles, &keys));
    assert!(!through_wildcard(&[], &roles, &keys));
}

#[test]
fn a_sensitive_key_is_never_held_through_a_wildcard() {
    let roles = role_sets(&[(1, &["rest:orders:*"], &[])]);

    assert!(!through_wildcard(
        &[global(1)],
        &roles,
        &[sensitive("rest:orders:POST /api/orders")]
    ));
}

fn through_wildcard_in(
    assignments: &[RoleAssignment],
    roles: &BTreeMap<RoleId, CompiledRoleSet>,
    keys: &[RequiredKey],
    project: Option<ProjectId>,
) -> bool {
    DecisionPolicy::holds_through_wildcard(&DecisionRequest {
        assignments,
        role_sets: roles,
        required: keys,
        project,
        now: at(NOW),
    })
}

#[test]
fn an_exact_grant_in_another_project_does_not_hide_a_global_wildcard_allow() {
    let roles = role_sets(&[
        (1, &["rest:orders:*"], &[]),
        (2, &["rest:orders:GET /api/orders/{}"], &[]),
    ]);
    let keys = [required("rest:orders:GET /api/orders/{}")];
    let assignments = [global(1), in_project(2, 2)];

    assert!(through_wildcard_in(
        &assignments,
        &roles,
        &keys,
        Some(project(1))
    ));
    assert!(through_wildcard_in(&assignments, &roles, &keys, None));
}

#[test]
fn an_exact_grant_in_the_same_project_keeps_the_allow_out_of_the_wildcard_lane() {
    let roles = role_sets(&[
        (1, &["rest:orders:*"], &[]),
        (2, &["rest:orders:GET /api/orders/{}"], &[]),
    ]);
    let keys = [required("rest:orders:GET /api/orders/{}")];
    let assignments = [global(1), in_project(2, 1)];

    assert!(!through_wildcard_in(
        &assignments,
        &roles,
        &keys,
        Some(project(1))
    ));
}

#[test]
fn a_global_wildcard_key_beside_a_project_exact_key_is_a_wildcard_allow_without_a_project() {
    let roles = role_sets(&[
        (1, &["rest:orders:*"], &[]),
        (2, &["rest:billing:GET /api/invoices"], &[]),
    ]);
    let keys = [
        required("rest:orders:GET /api/orders/{}"),
        required("rest:billing:GET /api/invoices"),
    ];
    let assignments = [global(1), in_project(2, 1)];

    assert!(through_wildcard_in(&assignments, &roles, &keys, None));
}
