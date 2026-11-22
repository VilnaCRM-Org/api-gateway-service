use proptest::prelude::*;
use rstest::rstest;

use super::{FlagDowngrade, RemovedGrant, RoleGrants, SpecDiff, WildcardGain};
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

const NONE: PermissionFlags = PermissionFlags::NONE;
const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const AUDIT: PermissionFlags = PermissionFlags::NONE.with_audit_always();
const BOTH: PermissionFlags = SENSITIVE.with_audit_always();

const ADMIN: &str = "00000000-0000-4000-8000-000000000001";
const VIEWER: &str = "00000000-0000-4000-8000-000000000002";

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn role(id: &str) -> RoleId {
    RoleId::parse(id).unwrap()
}

fn coordinate(value: &str) -> GraphQlCoordinate {
    GraphQlCoordinate::parse(value).unwrap()
}

fn coordinates(values: &[&str]) -> Vec<GraphQlCoordinate> {
    values.iter().map(|value| coordinate(value)).collect()
}

fn set(entries: &[(&str, PermissionFlags)]) -> CoordinateSet {
    entries
        .iter()
        .map(|(value, flags)| (coordinate(value), *flags))
        .collect()
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
    candidate: &CoordinateSet,
    active: &CoordinateSet,
    roles: &[(&str, &PermissionGrantSet)],
) -> SpecDiff {
    let roles: Vec<RoleGrants<'_>> = roles
        .iter()
        .map(|(id, grants)| RoleGrants {
            role: role(id),
            grants,
        })
        .collect();
    SpecDiff::compute(&billing(), candidate, active, &roles)
}

#[rstest]
#[case::identical(&[("Query.a", NONE)], &[("Query.a", NONE)], &[], &[])]
#[case::both_empty(&[], &[], &[], &[])]
#[case::first_version(&[("Query.a", NONE), ("Query.b", NONE)], &[], &["Query.a", "Query.b"], &[])]
#[case::everything_removed(&[], &[("Query.a", NONE)], &[], &["Query.a"])]
#[case::renamed_field(
    &[("Query.a", NONE), ("Query.c", NONE)],
    &[("Query.a", NONE), ("Query.b", NONE)],
    &["Query.c"],
    &["Query.b"]
)]
#[case::flags_do_not_add_or_remove(&[("Query.a", SENSITIVE)], &[("Query.a", NONE)], &[], &[])]
fn returns_the_added_and_removed_coordinates(
    #[case] candidate: &[(&str, PermissionFlags)],
    #[case] active: &[(&str, PermissionFlags)],
    #[case] added: &[&str],
    #[case] removed: &[&str],
) {
    let diff = diff(&set(candidate), &set(active), &[]);

    assert_eq!(diff.added(), coordinates(added).as_slice());
    assert_eq!(diff.removed(), coordinates(removed).as_slice());
}

#[test]
fn a_removed_coordinate_lists_the_roles_that_grant_its_exact_key() {
    let admin = grants(&[
        "gql:billing:Query.invoices",
        "gql:billing:Mutation.pay",
        "gql:billing:*",
    ]);
    let viewer = grants(&["gql:billing:Query.invoices", "gql:orders:Mutation.pay"]);
    let candidate = set(&[("Query.orders", NONE)]);
    let active = set(&[
        ("Query.invoices", NONE),
        ("Mutation.pay", NONE),
        ("Mutation.refund", NONE),
        ("Query.orders", NONE),
    ]);

    let diff = diff(
        &candidate,
        &active,
        &[(VIEWER, &viewer), (ADMIN, &admin), (ADMIN, &admin)],
    );

    assert_eq!(
        diff.removed(),
        coordinates(&["Mutation.pay", "Mutation.refund", "Query.invoices"]).as_slice()
    );
    assert_eq!(
        diff.removed_grants(),
        [
            RemovedGrant {
                coordinate: coordinate("Mutation.pay"),
                roles: vec![role(ADMIN)],
            },
            RemovedGrant {
                coordinate: coordinate("Query.invoices"),
                roles: vec![role(ADMIN), role(VIEWER)],
            },
        ]
    );
}

#[test]
fn a_wildcard_grant_lists_the_added_coordinates_it_would_cover() {
    let admin = grants(&[
        "gql:billing:*",
        "gql:billing:Query.*",
        "gql:orders:*",
        "rest:billing:*",
        "gql:billing:Query.invoices",
    ]);
    let viewer = grants(&["gql:billing:Mutation.*", "gql:billing:Invoice.*"]);
    let candidate = set(&[
        ("Query.invoices", NONE),
        ("Query.orders", NONE),
        ("Query.secrets", SENSITIVE),
        ("Mutation.pay", BOTH),
        ("Mutation.refund", AUDIT),
    ]);
    let active = set(&[("Query.invoices", NONE)]);

    let diff = diff(&candidate, &active, &[(VIEWER, &viewer), (ADMIN, &admin)]);

    assert_eq!(
        diff.wildcard_gains(),
        [
            WildcardGain {
                role: role(ADMIN),
                pattern: pattern("gql:billing:Query.*"),
                coordinates: coordinates(&["Query.orders"]),
            },
            WildcardGain {
                role: role(ADMIN),
                pattern: pattern("gql:billing:*"),
                coordinates: coordinates(&["Mutation.refund", "Query.orders"]),
            },
            WildcardGain {
                role: role(VIEWER),
                pattern: pattern("gql:billing:Mutation.*"),
                coordinates: coordinates(&["Mutation.refund"]),
            },
        ]
    );
    assert_eq!(diff.removed_grants(), []);
}

#[rstest]
#[case::sensitive_lost(SENSITIVE, NONE, true)]
#[case::audit_lost(AUDIT, NONE, true)]
#[case::one_of_two_lost(BOTH, AUDIT, true)]
#[case::swapped(SENSITIVE, AUDIT, true)]
#[case::kept(BOTH, BOTH, false)]
#[case::gained(NONE, BOTH, false)]
#[case::none(NONE, NONE, false)]
fn reports_a_coordinate_that_would_lose_a_flag(
    #[case] before: PermissionFlags,
    #[case] after: PermissionFlags,
    #[case] downgraded: bool,
) {
    let candidate = set(&[("Query.a", after), ("Query.new", NONE)]);
    let active = set(&[("Query.a", before), ("Query.old", BOTH)]);

    let diff = diff(&candidate, &active, &[]);

    let expected: Vec<FlagDowngrade> = downgraded
        .then(|| FlagDowngrade {
            coordinate: coordinate("Query.a"),
            before,
            after,
        })
        .into_iter()
        .collect();
    assert_eq!(diff.flag_downgrades(), expected.as_slice());
}

#[test]
fn a_diff_is_empty_only_without_changes() {
    let same = set(&[("Query.a", SENSITIVE)]);

    assert!(diff(&same, &same, &[]).is_empty());
    assert!(!diff(&set(&[("Query.a", NONE)]), &same, &[]).is_empty());
    assert!(!diff(&set(&[("Query.b", SENSITIVE)]), &same, &[]).is_empty());
    assert!(!diff(&CoordinateSet::new(), &same, &[]).is_empty());
}

/// A coordinate set drawn from a small universe, so that random sets overlap.
fn coordinate_set() -> impl Strategy<Value = CoordinateSet> {
    let types = prop::sample::select(vec!["Query", "Mutation", "Subscription", "Invoice"]);
    let fields = prop::sample::select(vec!["id", "invoices", "pay", "total", "updated"]);
    let flags = prop::sample::select(vec![NONE, SENSITIVE, AUDIT, BOTH]);
    prop::collection::vec((types, fields, flags), 0..20).prop_map(|entries| {
        entries
            .into_iter()
            .map(|(type_name, field, flags)| (coordinate(&format!("{type_name}.{field}")), flags))
            .collect::<CoordinateSet>()
    })
}

proptest! {
    #[test]
    fn the_diff_of_a_set_with_itself_is_empty(set in coordinate_set()) {
        let roles = grants(&["gql:billing:*", "gql:billing:Query.invoices"]);

        let diff = diff(&set, &set, &[(ADMIN, &roles)]);

        prop_assert!(diff.is_empty());
        prop_assert!(diff.added().is_empty());
        prop_assert!(diff.removed().is_empty());
        prop_assert!(diff.removed_grants().is_empty());
        prop_assert!(diff.wildcard_gains().is_empty());
        prop_assert!(diff.flag_downgrades().is_empty());
    }

    #[test]
    fn added_and_removed_swap_with_the_arguments(
        left in coordinate_set(),
        right in coordinate_set(),
    ) {
        let forward = diff(&left, &right, &[]);
        let backward = diff(&right, &left, &[]);

        prop_assert_eq!(forward.added(), backward.removed());
        prop_assert_eq!(forward.removed(), backward.added());
    }
}
