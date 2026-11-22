use proptest::prelude::{Just, Strategy, prop_oneof};
use proptest::sample::select;
use rstest::rstest;

use super::{GqlCoordinate, PermissionKey, PermissionKeyKind};
use crate::error::InvalidPermissionKey;
use crate::value_object::gql_name::GqlName;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::reserved_permission::{ReservedPermission, ServiceScope};
use crate::value_object::rest_template::RestTemplate;
use crate::value_object::service_name::ServiceName;

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

#[test]
fn a_rest_key_exposes_its_kind_service_method_and_template() {
    let key = PermissionKey::parse("rest:core:POST /api/projects/{}/members").unwrap();

    assert_eq!(key.kind(), PermissionKeyKind::Rest);
    assert_eq!(key.service(), &service("core"));
    assert_eq!(
        key,
        PermissionKey::Rest {
            service: service("core"),
            method: HttpMethod::Post,
            template: RestTemplate::parse("/api/projects/{}/members").unwrap(),
        }
    );
    assert_eq!(key.to_string(), "rest:core:POST /api/projects/{}/members");
}

#[test]
fn a_gql_key_exposes_its_kind_service_and_coordinate() {
    let key = PermissionKey::parse("gql:iam:Mutation.createRole").unwrap();

    assert_eq!(key.kind(), PermissionKeyKind::Gql);
    assert_eq!(key.service(), ServiceName::iam());
    assert_eq!(
        key,
        PermissionKey::Gql {
            service: service("iam"),
            coordinate: GqlCoordinate::Field {
                type_name: GqlName::parse("Mutation").unwrap(),
                field: GqlName::parse("createRole").unwrap(),
            },
        }
    );
    assert_eq!(key.to_string(), "gql:iam:Mutation.createRole");
}

#[test]
fn the_introspection_key_is_a_gql_key() {
    let key = PermissionKey::parse("gql:core:__introspection").unwrap();

    assert_eq!(key.kind(), PermissionKeyKind::Gql);
    assert_eq!(key.service(), &service("core"));
    assert_eq!(
        key,
        PermissionKey::Gql {
            service: service("core"),
            coordinate: GqlCoordinate::Introspection,
        }
    );
    assert_eq!(key.to_string(), "gql:core:__introspection");
}

#[rstest]
#[case("iam:grant:*", ReservedPermission::Grant(ServiceScope::All))]
#[case(
    "iam:validate:core",
    ReservedPermission::Validate(ServiceScope::Service(service("core")))
)]
#[case("iam:audit:read", ReservedPermission::AuditRead)]
fn a_reserved_key_belongs_to_the_iam_service(
    #[case] text: &str,
    #[case] reserved: ReservedPermission,
) {
    let key = PermissionKey::parse(text).unwrap();

    assert_eq!(key.kind(), PermissionKeyKind::Reserved);
    assert_eq!(key.service(), ServiceName::iam());
    assert_eq!(key, PermissionKey::Reserved(reserved));
    assert_eq!(key.to_string(), text);
}

#[rstest]
#[case(PermissionKeyKind::Rest, "rest")]
#[case(PermissionKeyKind::Gql, "gql")]
#[case(PermissionKeyKind::Reserved, "reserved")]
fn a_kind_has_a_stable_name(#[case] kind: PermissionKeyKind, #[case] name: &str) {
    assert_eq!(kind.as_str(), name);
}

#[rstest]
#[case("", InvalidPermissionKey::Kind)]
#[case("core", InvalidPermissionKey::Kind)]
#[case("http:core:GET /", InvalidPermissionKey::Kind)]
#[case("REST:core:GET /", InvalidPermissionKey::Kind)]
#[case("rest:Core:GET /", InvalidPermissionKey::Service)]
#[case("rest::GET /", InvalidPermissionKey::Service)]
#[case("gql:core_x:Query.a", InvalidPermissionKey::Service)]
#[case("rest:core", InvalidPermissionKey::Operation)]
#[case("gql:core", InvalidPermissionKey::Operation)]
#[case("rest:core:GET", InvalidPermissionKey::Operation)]
#[case("rest:core:get /a", InvalidPermissionKey::Method)]
#[case("rest:core:TRACE /a", InvalidPermissionKey::Method)]
#[case("rest:core:GET a", InvalidPermissionKey::Template)]
#[case("rest:core:GET /a/{id}", InvalidPermissionKey::Template)]
#[case("rest:core:GET /a b", InvalidPermissionKey::Template)]
#[case("rest:core:GET *", InvalidPermissionKey::Template)]
#[case("rest:core:*", InvalidPermissionKey::Operation)]
#[case("gql:core:Query", InvalidPermissionKey::Coordinate)]
#[case("gql:core:Query.", InvalidPermissionKey::Coordinate)]
#[case("gql:core:.roles", InvalidPermissionKey::Coordinate)]
#[case("gql:core:Query.roles.id", InvalidPermissionKey::Coordinate)]
#[case("gql:core:Query.*", InvalidPermissionKey::Coordinate)]
#[case("gql:core:*", InvalidPermissionKey::Coordinate)]
#[case("gql:core:__schema", InvalidPermissionKey::Coordinate)]
#[case("iam:cache:flush", InvalidPermissionKey::Reserved)]
#[case("iam:grant:Bad", InvalidPermissionKey::Service)]
fn a_malformed_key_is_rejected_with_its_code(
    #[case] text: &str,
    #[case] error: InvalidPermissionKey,
) {
    assert_eq!(PermissionKey::parse(text), Err(error));
}

fn service_names() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,8}(-[a-z0-9]{1,4}){0,3}"
}

fn rest_keys() -> impl Strategy<Value = String> {
    let methods = select(vec![
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
    ]);
    let templates = prop_oneof![
        Just("/".to_owned()),
        "(/([a-zA-Z0-9._~:-]{1,8}|\\{\\})){1,6}",
    ];
    (service_names(), methods, templates)
        .prop_map(|(service, method, template)| format!("rest:{service}:{method} {template}"))
}

fn gql_keys() -> impl Strategy<Value = String> {
    let coordinates = prop_oneof![
        Just("__introspection".to_owned()),
        "[A-Za-z][A-Za-z0-9_]{0,12}\\.[a-z][A-Za-z0-9_]{0,12}",
    ];
    (service_names(), coordinates)
        .prop_map(|(service, coordinate)| format!("gql:{service}:{coordinate}"))
}

fn reserved_keys() -> impl Strategy<Value = String> {
    let fixed = select(vec![
        "iam:validate:*",
        "iam:grant:*",
        "iam:grant:sensitive",
        "iam:grant:wildcard",
        "iam:spec:*",
        "iam:audit:read",
        "iam:revoke:sessions",
        "iam:revoke:global",
        "iam:policy:resync",
        "iam:route:anonymous",
        "iam:route:*",
    ])
    .prop_map(str::to_owned);
    let scoped = (
        select(vec!["validate", "grant", "spec", "route"]),
        service_names(),
    )
        .prop_filter("a reserved word is not a service", |(_, name)| {
            !matches!(name.as_str(), "sensitive" | "wildcard" | "anonymous")
        })
        .prop_map(|(family, name)| format!("iam:{family}:{name}"));
    prop_oneof![fixed, scoped]
}

fn keys() -> impl Strategy<Value = String> {
    prop_oneof![rest_keys(), gql_keys(), reserved_keys()]
}

proptest::proptest! {
    #[test]
    fn formatting_a_parsed_key_and_parsing_it_again_returns_the_same_key(text in keys()) {
        let key = PermissionKey::parse(&text).unwrap();
        let printed = key.to_string();

        proptest::prop_assert_eq!(&printed, &text);
        proptest::prop_assert_eq!(PermissionKey::parse(&printed), Ok(key));
    }

    #[test]
    fn parsing_never_panics_and_accepted_text_prints_back(text in "\\PC{0,40}") {
        if let Ok(key) = PermissionKey::parse(&text) {
            proptest::prop_assert_eq!(key.to_string(), text);
        }
    }
}
