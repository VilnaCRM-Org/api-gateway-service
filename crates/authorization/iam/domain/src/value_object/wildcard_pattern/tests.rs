use proptest::prelude::{Strategy, prop_oneof};
use proptest::sample::select;
use rstest::rstest;

use super::WildcardPattern;
use crate::error::InvalidPermissionKey;
use crate::value_object::gql_name::GqlName;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::service_name::ServiceName;

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

#[rstest]
#[case(
    "gql:core:Query.*",
    WildcardPattern::GqlType { service: service("core"), type_name: GqlName::parse("Query").unwrap() }
)]
#[case("gql:core:*", WildcardPattern::GqlService { service: service("core") })]
#[case(
    "rest:core:GET *",
    WildcardPattern::RestMethod { service: service("core"), method: HttpMethod::Get }
)]
#[case("rest:core:*", WildcardPattern::RestService { service: service("core") })]
fn accepts_exactly_the_four_forms(#[case] text: &str, #[case] expected: WildcardPattern) {
    let pattern = WildcardPattern::parse(text).unwrap();

    assert_eq!(pattern, expected);
    assert_eq!(pattern.service(), &service("core"));
    assert_eq!(pattern.to_string(), text);
}

#[rstest]
#[case("gql:core:*.field", InvalidPermissionKey::Wildcard)]
#[case("gql:core:Query*", InvalidPermissionKey::Wildcard)]
#[case("gql:core:Query.f*", InvalidPermissionKey::Wildcard)]
#[case("gql:core:**", InvalidPermissionKey::Wildcard)]
#[case("gql:core:Query.roles", InvalidPermissionKey::Wildcard)]
#[case("gql:core:__x.*", InvalidPermissionKey::Wildcard)]
#[case("gql:core:.*", InvalidPermissionKey::Wildcard)]
#[case("rest:core:GET /api/*", InvalidPermissionKey::Wildcard)]
#[case("rest:core:* /api", InvalidPermissionKey::Wildcard)]
#[case("rest:core:* *", InvalidPermissionKey::Wildcard)]
#[case("rest:core:get *", InvalidPermissionKey::Wildcard)]
#[case("rest:core:GET  *", InvalidPermissionKey::Wildcard)]
#[case("rest:core:GET /api", InvalidPermissionKey::Wildcard)]
#[case("rest:core", InvalidPermissionKey::Wildcard)]
#[case("gql:core", InvalidPermissionKey::Wildcard)]
#[case("rest:*:*", InvalidPermissionKey::Service)]
#[case("gql:Core:*", InvalidPermissionKey::Service)]
#[case("iam:grant:*", InvalidPermissionKey::Wildcard)]
#[case("*", InvalidPermissionKey::Wildcard)]
#[case("", InvalidPermissionKey::Wildcard)]
fn rejects_near_misses(#[case] text: &str, #[case] error: InvalidPermissionKey) {
    assert_eq!(WildcardPattern::parse(text), Err(error));
}

fn patterns() -> impl Strategy<Value = String> {
    let services = "[a-z][a-z0-9]{0,8}(-[a-z0-9]{1,4}){0,2}";
    let methods = select(vec![
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
    ]);
    prop_oneof![
        (services, "[A-Za-z][A-Za-z0-9_]{0,12}").prop_map(|(s, t)| format!("gql:{s}:{t}.*")),
        services.prop_map(|s| format!("gql:{s}:*")),
        (services, methods).prop_map(|(s, m)| format!("rest:{s}:{m} *")),
        services.prop_map(|s| format!("rest:{s}:*")),
    ]
}

proptest::proptest! {
    #[test]
    fn a_parsed_pattern_prints_back_to_its_text(text in patterns()) {
        let pattern = WildcardPattern::parse(&text).unwrap();

        proptest::prop_assert_eq!(pattern.to_string(), text);
    }
}
