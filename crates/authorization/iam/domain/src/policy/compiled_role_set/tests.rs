use rstest::rstest;

use super::{CompiledRoleSet, GrantStatus};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::permission_key::PermissionKey;

fn grant(text: &str) -> PermissionGrant {
    PermissionGrant::parse(text).unwrap()
}

fn key(text: &str) -> PermissionKey {
    PermissionKey::parse(text).unwrap()
}

fn active(texts: &[&str]) -> CompiledRoleSet {
    CompiledRoleSet::compile(texts.iter().map(|text| (grant(text), GrantStatus::Active)))
}

#[test]
fn an_empty_role_holds_nothing() {
    let set = CompiledRoleSet::compile(Vec::new());

    assert!(set.is_empty());
    assert_eq!(set.key_count(), 0);
    assert_eq!(set.wildcard_count(), 0);
    assert!(!set.holds(&key("gql:orders:Query.order"), PermissionFlags::NONE));
}

#[test]
fn a_role_holds_its_exact_keys() {
    let set = active(&["rest:orders:GET /api/orders", "gql:orders:Query.order"]);

    assert!(!set.is_empty());
    assert_eq!(set.key_count(), 2);
    assert!(set.holds(&key("rest:orders:GET /api/orders"), PermissionFlags::NONE));
    assert!(set.holds(&key("gql:orders:Query.order"), PermissionFlags::NONE));
    assert!(!set.holds(&key("gql:orders:Query.orders"), PermissionFlags::NONE));
}

#[test]
fn an_exact_grant_holds_a_sensitive_key() {
    let set = active(&["rest:orders:POST /api/orders"]);
    let sensitive = PermissionFlags::NONE.with_sensitive();

    assert!(set.holds(&key("rest:orders:POST /api/orders"), sensitive));
}

#[test]
fn a_wildcard_holds_the_keys_it_covers_but_never_a_sensitive_one() {
    let set = active(&["rest:orders:*"]);
    let sensitive = PermissionFlags::NONE.with_sensitive();

    assert_eq!(set.wildcard_count(), 1);
    assert!(!set.is_empty());
    assert!(set.holds(&key("rest:orders:GET /api/orders"), PermissionFlags::NONE));
    assert!(!set.holds(&key("rest:orders:POST /api/orders"), sensitive));
    assert!(!set.holds(
        &key("rest:billing:GET /api/invoices"),
        PermissionFlags::NONE
    ));
}

#[test]
fn orphaned_grants_are_left_out() {
    let set = CompiledRoleSet::compile([
        (grant("gql:orders:Query.order"), GrantStatus::Orphaned),
        (grant("gql:orders:*"), GrantStatus::Orphaned),
        (grant("rest:orders:GET /api/orders"), GrantStatus::Active),
    ]);

    assert_eq!(set.key_count(), 1);
    assert_eq!(set.wildcard_count(), 0);
    assert!(!set.holds(&key("gql:orders:Query.order"), PermissionFlags::NONE));
    assert!(set.holds(&key("rest:orders:GET /api/orders"), PermissionFlags::NONE));
}

#[test]
fn a_role_of_only_orphaned_grants_is_empty() {
    let set = CompiledRoleSet::compile([(grant("gql:orders:*"), GrantStatus::Orphaned)]);

    assert!(set.is_empty());
}

#[test]
fn an_active_grant_set_compiles_every_grant() {
    let grants =
        PermissionGrantSet::new([grant("gql:orders:Query.*"), grant("iam:audit:read")]).unwrap();
    let set = CompiledRoleSet::from_active(&grants);

    assert_eq!(set.key_count(), 1);
    assert_eq!(set.wildcard_count(), 1);
    assert!(set.holds(&key("gql:orders:Query.order"), PermissionFlags::NONE));
    assert!(set.holds(&key("iam:audit:read"), PermissionFlags::NONE));
}

#[rstest]
#[case("iam:grant:*", "iam:grant:orders", true)]
#[case("iam:grant:*", "iam:grant:iam", true)]
#[case("iam:grant:orders", "iam:grant:orders", true)]
#[case("iam:grant:orders", "iam:grant:billing", false)]
#[case("iam:spec:*", "iam:spec:orders", true)]
#[case("iam:spec:*", "iam:spec:iam", false)]
#[case("iam:grant:*", "iam:grant:sensitive", false)]
#[case("iam:grant:*", "iam:validate:orders", false)]
#[case("iam:audit:read", "iam:revoke:global", false)]
fn a_reserved_key_holds_exactly_the_reserved_keys_it_covers(
    #[case] held: &str,
    #[case] required: &str,
    #[case] holds: bool,
) {
    assert_eq!(
        active(&[held]).holds(&key(required), PermissionFlags::NONE),
        holds
    );
}

#[test]
fn a_reserved_key_never_holds_a_rest_or_graphql_key() {
    let set = active(&["iam:grant:*"]);

    assert!(!set.holds(&key("rest:iam:POST /api/roles"), PermissionFlags::NONE));
    assert!(!set.holds(&key("gql:iam:Mutation.createRole"), PermissionFlags::NONE));
}

#[test]
fn a_key_is_held_only_through_a_wildcard_when_no_exact_grant_covers_it() {
    let flags = PermissionFlags::NONE;
    let wildcard = active(&["rest:orders:*"]);
    let exact = active(&["rest:orders:GET /api/orders", "rest:orders:*"]);
    let target = key("rest:orders:GET /api/orders");

    assert!(wildcard.holds_only_through_wildcard(&target, flags));
    assert!(!exact.holds_only_through_wildcard(&target, flags));
    assert!(!active(&[]).holds_only_through_wildcard(&target, flags));
}
