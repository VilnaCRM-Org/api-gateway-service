use rstest::rstest;

use super::WildcardMatcher;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::wildcard_pattern::WildcardPattern;

fn key(text: &str) -> PermissionKey {
    PermissionKey::parse(text).unwrap()
}

fn pattern(text: &str) -> WildcardPattern {
    WildcardPattern::parse(text).unwrap()
}

fn probes(text: &str) -> Vec<String> {
    WildcardMatcher::probes(&key(text), PermissionFlags::NONE)
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn a_rest_key_is_probed_by_its_method_and_its_service_pattern() {
    assert_eq!(
        probes("rest:orders:GET /api/orders/{}"),
        ["rest:orders:GET *", "rest:orders:*"]
    );
}

#[test]
fn a_graphql_field_is_probed_by_its_type_and_its_service_pattern() {
    assert_eq!(
        probes("gql:orders:Mutation.cancelOrder"),
        ["gql:orders:Mutation.*", "gql:orders:*"]
    );
}

#[test]
fn introspection_is_probed_by_the_service_pattern_only() {
    assert_eq!(probes("gql:orders:__introspection"), ["gql:orders:*"]);
}

#[rstest]
#[case("iam:grant:*")]
#[case("iam:audit:read")]
fn a_reserved_key_is_probed_by_no_pattern(#[case] text: &str) {
    assert_eq!(probes(text), Vec::<String>::new());
}

#[rstest]
#[case("rest:orders:GET /api/orders")]
#[case("gql:orders:Query.order")]
#[case("gql:orders:__introspection")]
fn a_sensitive_key_is_probed_by_no_pattern(#[case] text: &str) {
    let sensitive = PermissionFlags::NONE.with_sensitive();

    assert_eq!(
        WildcardMatcher::probes(&key(text), sensitive),
        Vec::<WildcardPattern>::new()
    );
}

#[rstest]
#[case("rest:orders:*", "rest:orders:DELETE /api/orders/{}", true)]
#[case("rest:orders:GET *", "rest:orders:GET /api/orders", true)]
#[case("rest:orders:GET *", "rest:orders:POST /api/orders", false)]
#[case("rest:orders:*", "rest:billing:GET /api/invoices", false)]
#[case("rest:orders:*", "gql:orders:Query.order", false)]
#[case("gql:orders:*", "gql:orders:Query.order", true)]
#[case("gql:orders:*", "gql:orders:__introspection", true)]
#[case("gql:orders:Query.*", "gql:orders:Query.order", true)]
#[case("gql:orders:Query.*", "gql:orders:Mutation.cancelOrder", false)]
#[case("gql:orders:Query.*", "gql:orders:__introspection", false)]
#[case("gql:orders:*", "gql:billing:Query.invoice", false)]
#[case("gql:orders:*", "rest:orders:GET /api/orders", false)]
#[case("gql:iam:*", "iam:audit:read", false)]
fn a_pattern_covers_exactly_the_keys_of_its_form(
    #[case] pattern_text: &str,
    #[case] key_text: &str,
    #[case] covered: bool,
) {
    assert_eq!(
        WildcardMatcher::covers(
            &pattern(pattern_text),
            &key(key_text),
            PermissionFlags::NONE
        ),
        covered
    );
}

#[rstest]
#[case("rest:orders:*", "rest:orders:POST /api/orders")]
#[case("rest:orders:POST *", "rest:orders:POST /api/orders")]
#[case("gql:orders:*", "gql:orders:Mutation.cancelOrder")]
#[case("gql:orders:Mutation.*", "gql:orders:Mutation.cancelOrder")]
fn no_pattern_covers_a_sensitive_key(#[case] pattern_text: &str, #[case] key_text: &str) {
    let flags = PermissionFlags::NONE.with_sensitive().with_audit_always();

    assert!(!WildcardMatcher::covers(
        &pattern(pattern_text),
        &key(key_text),
        flags
    ));
}

#[test]
fn audit_always_alone_does_not_stop_a_pattern() {
    let flags = PermissionFlags::NONE.with_audit_always();

    assert!(WildcardMatcher::covers(
        &pattern("rest:orders:*"),
        &key("rest:orders:GET /api/orders"),
        flags
    ));
}
