mod properties;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use super::{EffectivePermission, EffectivePermissionComposer, EffectivePermissionFilter};
use crate::policy::compiled_role_set::{CompiledRoleSet, GrantStatus};
use crate::policy::decision_policy::RoleAssignment;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::{ProjectId, RoleId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::scope_set::ScopeSet;
use crate::value_object::service_name::ServiceName;

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

fn key(text: &str) -> PermissionKey {
    PermissionKey::parse(text).unwrap()
}

fn grant(text: &str) -> PermissionGrant {
    PermissionGrant::parse(text).unwrap()
}

fn roles(specs: &[(u8, &[&str])]) -> BTreeMap<RoleId, CompiledRoleSet> {
    specs
        .iter()
        .map(|(number, grants)| {
            let compiled = CompiledRoleSet::compile(
                grants.iter().map(|text| (grant(text), GrantStatus::Active)),
            );
            (role(*number), compiled)
        })
        .collect()
}

fn global(number: u8, expires: Option<u64>) -> RoleAssignment {
    RoleAssignment::new(role(number), AssignmentScope::Global, expires.map(at))
}

fn in_project(number: u8, project_number: u8, expires: Option<u64>) -> RoleAssignment {
    RoleAssignment::new(
        role(number),
        AssignmentScope::Project(project(project_number)),
        expires.map(at),
    )
}

fn compose(
    assignments: &[RoleAssignment],
    sets: &BTreeMap<RoleId, CompiledRoleSet>,
    filter: &EffectivePermissionFilter,
) -> super::UserRolePermission {
    EffectivePermissionComposer::compose(
        PolicyVersion::new(7).unwrap(),
        assignments,
        sets,
        filter,
        at(NOW),
    )
}

fn entry<'a>(
    read_model: &'a super::UserRolePermission,
    text: &str,
) -> Option<&'a EffectivePermission> {
    read_model
        .permissions()
        .iter()
        .find(|entry| entry.grant() == &grant(text))
}

#[test]
fn a_subject_without_assignments_holds_nothing_at_the_policy_version() {
    let read_model = compose(&[], &roles(&[]), &EffectivePermissionFilter::default());

    assert_eq!(read_model.permissions(), []);
    assert_eq!(read_model.policy_version().value(), 7);
}

#[test]
fn a_key_lists_its_granting_roles_scopes_and_shortest_expiry() {
    let sets = roles(&[
        (1, &["rest:orders:GET /api/orders"]),
        (2, &["rest:orders:GET /api/orders"]),
    ]);
    let assignments = [
        global(1, Some(NOW + 500)),
        in_project(2, 1, Some(NOW + 100)),
        in_project(2, 2, None),
    ];

    let read_model = compose(&assignments, &sets, &EffectivePermissionFilter::default());

    let listed = entry(&read_model, "rest:orders:GET /api/orders").unwrap();
    assert_eq!(listed.roles(), &BTreeSet::from([role(1), role(2)]));
    assert_eq!(listed.scopes(), &ScopeSet::All);
    assert_eq!(listed.expires_at(), Some(at(NOW + 100)));
    assert_eq!(read_model.permissions().len(), 1);
}

#[test]
fn a_project_assignment_lists_the_projects_and_no_expiry_when_none_expires() {
    let sets = roles(&[(1, &["gql:orders:Query.order"])]);
    let assignments = [in_project(1, 2, None), in_project(1, 1, None)];

    let read_model = compose(&assignments, &sets, &EffectivePermissionFilter::default());

    let listed = entry(&read_model, "gql:orders:Query.order").unwrap();
    assert_eq!(
        listed.scopes(),
        &ScopeSet::Projects(BTreeSet::from([project(1), project(2)]))
    );
    assert_eq!(listed.expires_at(), None);
}

#[test]
fn a_wildcard_is_listed_as_itself_after_the_exact_keys() {
    let sets = roles(&[(1, &["rest:orders:*", "gql:orders:Query.order"])]);

    let read_model = compose(
        &[global(1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );

    let texts: Vec<String> = read_model
        .permissions()
        .iter()
        .map(|entry| entry.grant().to_string())
        .collect();
    assert_eq!(texts, ["gql:orders:Query.order", "rest:orders:*"]);
}

#[test]
fn an_expired_assignment_and_an_unknown_role_contribute_nothing() {
    let sets = roles(&[(1, &["rest:orders:GET /api/orders"])]);
    let assignments = [global(1, Some(NOW)), global(9, None)];

    let read_model = compose(&assignments, &sets, &EffectivePermissionFilter::default());

    assert_eq!(read_model.permissions(), []);
}

#[test]
fn an_orphaned_grant_is_left_out() {
    let compiled = CompiledRoleSet::compile([
        (grant("rest:orders:GET /api/orders"), GrantStatus::Orphaned),
        (grant("gql:orders:Query.order"), GrantStatus::Active),
    ]);
    let sets = BTreeMap::from([(role(1), compiled)]);

    let read_model = compose(
        &[global(1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );

    assert!(entry(&read_model, "rest:orders:GET /api/orders").is_none());
    assert!(entry(&read_model, "gql:orders:Query.order").is_some());
}

#[test]
fn a_reserved_key_counts_only_through_a_global_assignment() {
    let sets = roles(&[(1, &["iam:audit:read", "rest:orders:GET /api/orders"])]);

    let through_project = compose(
        &[in_project(1, 1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );
    let through_global = compose(
        &[global(1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );

    assert!(entry(&through_project, "iam:audit:read").is_none());
    assert!(entry(&through_project, "rest:orders:GET /api/orders").is_some());
    assert!(entry(&through_global, "iam:audit:read").is_some());
}

#[test]
fn the_project_filter_keeps_global_assignments_and_those_of_the_project() {
    let sets = roles(&[
        (1, &["rest:orders:GET /api/orders"]),
        (2, &["gql:orders:Query.order"]),
        (3, &["rest:billing:GET /api/invoices"]),
    ]);
    let assignments = [
        global(1, None),
        in_project(2, 1, None),
        in_project(3, 2, None),
    ];
    let filter = EffectivePermissionFilter {
        project: Some(project(1)),
        service: None,
    };

    let read_model = compose(&assignments, &sets, &filter);

    assert!(entry(&read_model, "rest:orders:GET /api/orders").is_some());
    assert!(entry(&read_model, "gql:orders:Query.order").is_some());
    assert!(entry(&read_model, "rest:billing:GET /api/invoices").is_none());
}

#[test]
fn the_service_filter_keeps_the_keys_and_wildcards_of_the_service() {
    let sets = roles(&[(
        1,
        &[
            "rest:orders:GET /api/orders",
            "rest:billing:*",
            "rest:billing:GET /api/invoices",
        ],
    )]);
    let filter = EffectivePermissionFilter {
        project: None,
        service: Some(ServiceName::new("billing").unwrap()),
    };

    let read_model = compose(&[global(1, None)], &sets, &filter);

    let texts: Vec<String> = read_model
        .permissions()
        .iter()
        .map(|entry| entry.grant().to_string())
        .collect();
    assert_eq!(texts, ["rest:billing:GET /api/invoices", "rest:billing:*"]);
}

#[test]
fn scopes_of_unions_the_entries_that_cover_a_key() {
    let sets = roles(&[
        (1, &["rest:orders:*"]),
        (2, &["rest:orders:GET /api/orders"]),
    ]);
    let assignments = [in_project(1, 1, None), in_project(2, 2, None)];
    let read_model = compose(&assignments, &sets, &EffectivePermissionFilter::default());

    let covered = read_model.scopes_of(&key("rest:orders:GET /api/orders"), PermissionFlags::NONE);
    let sensitive = read_model.scopes_of(
        &key("rest:orders:POST /api/orders"),
        PermissionFlags::NONE.with_sensitive(),
    );
    let other = read_model.scopes_of(
        &key("rest:billing:GET /api/invoices"),
        PermissionFlags::NONE,
    );

    assert_eq!(
        covered,
        ScopeSet::Projects(BTreeSet::from([project(1), project(2)]))
    );
    assert!(sensitive.is_empty());
    assert!(other.is_empty());
}

#[test]
fn a_global_wildcard_covers_every_project() {
    let sets = roles(&[(1, &["gql:orders:*"])]);
    let read_model = compose(
        &[global(1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );

    let covered = read_model.scopes_of(&key("gql:orders:Query.order"), PermissionFlags::NONE);

    assert_eq!(covered, ScopeSet::All);
}

#[test]
fn a_reserved_wildcard_key_covers_the_reserved_keys_it_names() {
    let sets = roles(&[(1, &["iam:validate:*"])]);
    let read_model = compose(
        &[global(1, None)],
        &sets,
        &EffectivePermissionFilter::default(),
    );

    let covered = read_model.scopes_of(&key("iam:validate:orders"), PermissionFlags::NONE);

    assert_eq!(covered, ScopeSet::All);
}
