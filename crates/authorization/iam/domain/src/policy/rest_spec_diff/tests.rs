use rstest::rstest;

use super::{RemovedRestGrant, RestFlagDowngrade, RestSpecDiff, RestWildcardGain};
use crate::policy::spec_diff::RoleGrants;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::RoleId;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::rest_operation_set::{RestOperation, RestOperationKey, RestOperationSet};
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

const NONE: PermissionFlags = PermissionFlags::NONE;
const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const AUDIT: PermissionFlags = PermissionFlags::NONE.with_audit_always();

const ADMIN: &str = "00000000-0000-4000-8000-000000000001";
const VIEWER: &str = "00000000-0000-4000-8000-000000000002";

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn role(id: &str) -> RoleId {
    RoleId::parse(id).unwrap()
}

/// `METHOD /path`, as an operation key.
fn key(value: &str) -> RestOperationKey {
    let (method, path) = value.split_once(' ').unwrap();
    RestOperationKey {
        method: HttpMethod::parse(method).unwrap(),
        template: PathTemplate::from_openapi_path(path).unwrap(),
    }
}

fn keys(values: &[&str]) -> Vec<RestOperationKey> {
    values.iter().map(|value| key(value)).collect()
}

fn set(entries: &[(&str, PermissionFlags)]) -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for (value, flags) in entries {
        let key = key(value);
        set.insert(RestOperation {
            method: key.method,
            template: key.template,
            label: None,
            flags: *flags,
        })
        .unwrap();
    }
    set
}

fn grants(values: &[&str]) -> PermissionGrantSet {
    PermissionGrantSet::new(
        values
            .iter()
            .map(|value| PermissionGrant::parse(value).unwrap()),
    )
    .unwrap()
}

fn pattern(value: &str) -> WildcardPattern {
    WildcardPattern::parse(value).unwrap()
}

fn diff(
    candidate: &RestOperationSet,
    active: &RestOperationSet,
    roles: &[(&str, &PermissionGrantSet)],
) -> RestSpecDiff {
    let roles: Vec<RoleGrants<'_>> = roles
        .iter()
        .map(|(id, grants)| RoleGrants {
            role: role(id),
            grants,
        })
        .collect();
    RestSpecDiff::compute(&billing(), candidate, active, &roles)
}

#[rstest]
#[case::identical(&[("GET /a", NONE)], &[("GET /a", NONE)], &[], &[])]
#[case::both_empty(&[], &[], &[], &[])]
#[case::first_version(&[("GET /a", NONE), ("POST /a", NONE)], &[], &["GET /a", "POST /a"], &[])]
#[case::everything_removed(&[], &[("GET /a", NONE)], &[], &["GET /a"])]
#[case::method_is_part_of_the_key(
    &[("GET /a", NONE), ("PUT /a", NONE)],
    &[("GET /a", NONE), ("POST /a", NONE)],
    &["PUT /a"],
    &["POST /a"]
)]
#[case::flags_do_not_add_or_remove(&[("GET /a", SENSITIVE)], &[("GET /a", NONE)], &[], &[])]
fn returns_the_added_and_removed_operations(
    #[case] candidate: &[(&str, PermissionFlags)],
    #[case] active: &[(&str, PermissionFlags)],
    #[case] added: &[&str],
    #[case] removed: &[&str],
) {
    let diff = diff(&set(candidate), &set(active), &[]);

    assert_eq!(diff.added(), keys(added).as_slice());
    assert_eq!(diff.removed(), keys(removed).as_slice());
}

#[test]
fn a_removed_operation_lists_the_roles_that_grant_its_exact_key() {
    let admin = grants(&[
        "rest:billing:GET /invoices",
        "rest:billing:POST /invoices/{}/pay",
        "rest:billing:*",
        "rest:orders:POST /invoices/{}/pay",
    ]);
    let viewer = grants(&["rest:billing:GET /invoices"]);
    let candidate = set(&[("GET /orders", NONE)]);
    let active = set(&[
        ("GET /invoices", NONE),
        ("POST /invoices/{id}/pay", NONE),
        ("DELETE /invoices", NONE),
        ("GET /orders", NONE),
    ]);

    let diff = diff(
        &candidate,
        &active,
        &[(VIEWER, &viewer), (ADMIN, &admin), (ADMIN, &admin)],
    );

    assert_eq!(
        diff.removed_grants(),
        [
            RemovedRestGrant {
                operation: key("GET /invoices"),
                roles: vec![role(ADMIN), role(VIEWER)],
            },
            RemovedRestGrant {
                operation: key("POST /invoices/{id}/pay"),
                roles: vec![role(ADMIN)],
            },
        ]
    );
}

#[test]
fn a_wildcard_grant_lists_the_added_operations_it_would_cover() {
    let admin = grants(&["rest:billing:GET *", "rest:billing:POST *", "rest:orders:*"]);
    let viewer = grants(&["rest:billing:*", "gql:billing:*", "rest:billing:GET /a"]);
    let candidate = set(&[
        ("GET /a", NONE),
        ("GET /b", NONE),
        ("POST /c", NONE),
        ("DELETE /d", NONE),
        ("GET /secret", SENSITIVE),
    ]);

    let diff = diff(
        &candidate,
        &RestOperationSet::new(),
        &[(VIEWER, &viewer), (ADMIN, &admin)],
    );

    assert_eq!(
        diff.wildcard_gains(),
        [
            RestWildcardGain {
                role: role(ADMIN),
                pattern: pattern("rest:billing:GET *"),
                operations: keys(&["GET /a", "GET /b"]),
            },
            RestWildcardGain {
                role: role(ADMIN),
                pattern: pattern("rest:billing:POST *"),
                operations: keys(&["POST /c"]),
            },
            RestWildcardGain {
                role: role(VIEWER),
                pattern: pattern("rest:billing:*"),
                operations: keys(&["GET /a", "GET /b", "POST /c", "DELETE /d"]),
            },
        ]
    );
}

#[test]
fn a_wildcard_gains_nothing_without_an_added_operation() {
    let admin = grants(&["rest:billing:*"]);
    let both = set(&[("GET /a", NONE)]);

    let diff = diff(&both, &both, &[(ADMIN, &admin)]);

    assert_eq!(diff.wildcard_gains().len(), 0);
    assert!(diff.is_empty());
}

#[rstest]
#[case::sensitive_dropped(SENSITIVE, NONE, true)]
#[case::audit_dropped(AUDIT, NONE, true)]
#[case::one_of_two_dropped(SENSITIVE.with_audit_always(), SENSITIVE, true)]
#[case::flag_gained(NONE, SENSITIVE, false)]
#[case::unchanged(AUDIT, AUDIT, false)]
fn lists_the_operations_that_lose_a_flag(
    #[case] before: PermissionFlags,
    #[case] after: PermissionFlags,
    #[case] downgraded: bool,
) {
    let diff = diff(&set(&[("GET /a", after)]), &set(&[("GET /a", before)]), &[]);

    let expected: Vec<RestFlagDowngrade> = downgraded
        .then(|| RestFlagDowngrade {
            operation: key("GET /a"),
            before,
            after,
        })
        .into_iter()
        .collect();
    assert_eq!(diff.flag_downgrades(), expected.as_slice());
    assert_eq!(diff.is_empty(), !downgraded);
}

#[test]
fn a_flag_downgrade_alone_is_a_change() {
    let diff = diff(
        &set(&[("GET /a", NONE)]),
        &set(&[("GET /a", SENSITIVE)]),
        &[],
    );

    assert_eq!(diff.added().len(), 0);
    assert_eq!(diff.removed().len(), 0);
    assert!(!diff.is_empty());
}

#[test]
fn a_grant_of_another_service_or_kind_is_not_an_exact_grant_of_the_operation() {
    let admin = grants(&["rest:orders:GET /a", "gql:billing:Query.a"]);

    let diff = diff(
        &RestOperationSet::new(),
        &set(&[("GET /a", NONE)]),
        &[(ADMIN, &admin)],
    );

    assert_eq!(diff.removed(), keys(&["GET /a"]).as_slice());
    assert_eq!(diff.removed_grants().len(), 0);
}
