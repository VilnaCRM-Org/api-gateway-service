use rstest::rstest;

use super::{ReservedPermission, ServiceScope};
use crate::error::InvalidPermissionKey;
use crate::value_object::service_name::ServiceName;

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn on(name: &str) -> ServiceScope {
    ServiceScope::Service(service(name))
}

fn parse(text: &str) -> ReservedPermission {
    ReservedPermission::parse(text).unwrap()
}

#[rstest]
#[case("iam:validate:core", ReservedPermission::Validate(on("core")))]
#[case("iam:validate:*", ReservedPermission::Validate(ServiceScope::All))]
#[case("iam:grant:core", ReservedPermission::Grant(on("core")))]
#[case("iam:grant:*", ReservedPermission::Grant(ServiceScope::All))]
#[case("iam:grant:sensitive", ReservedPermission::GrantSensitive)]
#[case("iam:grant:wildcard", ReservedPermission::GrantWildcard)]
#[case("iam:spec:core", ReservedPermission::Spec(on("core")))]
#[case("iam:spec:*", ReservedPermission::Spec(ServiceScope::All))]
#[case("iam:audit:read", ReservedPermission::AuditRead)]
#[case("iam:revoke:sessions", ReservedPermission::RevokeSessions)]
#[case("iam:revoke:global", ReservedPermission::RevokeGlobal)]
#[case("iam:policy:resync", ReservedPermission::PolicyResync)]
#[case("iam:route:anonymous", ReservedPermission::RouteAnonymous)]
#[case("iam:route:core", ReservedPermission::Route(on("core")))]
#[case("iam:route:*", ReservedPermission::Route(ServiceScope::All))]
fn every_reserved_key_parses_and_prints_back(
    #[case] text: &str,
    #[case] expected: ReservedPermission,
) {
    let permission = parse(text);

    assert_eq!(permission, expected);
    assert_eq!(permission.to_string(), text);
}

#[rstest]
#[case("iam:cache:flush", InvalidPermissionKey::Reserved)]
#[case("iam:audit:write", InvalidPermissionKey::Reserved)]
#[case("iam:revoke:all", InvalidPermissionKey::Reserved)]
#[case("iam:policy:flush", InvalidPermissionKey::Reserved)]
#[case("iam:validate", InvalidPermissionKey::Reserved)]
#[case("iam:", InvalidPermissionKey::Reserved)]
#[case("iam:validate:Core", InvalidPermissionKey::Service)]
#[case("iam:grant:", InvalidPermissionKey::Service)]
#[case("iam:spec:a--b", InvalidPermissionKey::Service)]
#[case("iam:route:core:extra", InvalidPermissionKey::Service)]
#[case("gql:iam:Query.roles", InvalidPermissionKey::Kind)]
#[case("validate:core", InvalidPermissionKey::Kind)]
#[case("", InvalidPermissionKey::Kind)]
fn rejects_unknown_and_malformed_keys(#[case] text: &str, #[case] error: InvalidPermissionKey) {
    assert_eq!(ReservedPermission::parse(text), Err(error));
}

#[rstest]
#[case("core")]
#[case("iam")]
fn grant_all_covers_every_service(#[case] name: &str) {
    assert!(parse("iam:grant:*").covers_service(&service(name)));
    assert!(parse("iam:validate:*").covers_service(&service(name)));
}

#[rstest]
#[case("iam:spec:*")]
#[case("iam:route:*")]
fn spec_all_and_route_all_cover_every_service_except_iam(#[case] text: &str) {
    let permission = parse(text);

    assert!(permission.covers_service(&service("core")));
    assert!(permission.covers_service(&service("user-service")));
    assert!(!permission.covers_service(ServiceName::iam()));
}

#[rstest]
#[case("iam:validate:core")]
#[case("iam:grant:core")]
#[case("iam:spec:core")]
#[case("iam:route:core")]
fn a_service_key_covers_only_its_own_service(#[case] text: &str) {
    let permission = parse(text);

    assert!(permission.covers_service(&service("core")));
    assert!(!permission.covers_service(&service("other")));
    assert!(!permission.covers_service(ServiceName::iam()));
}

#[rstest]
#[case("iam:spec:iam")]
#[case("iam:route:iam")]
fn an_explicit_iam_key_covers_iam(#[case] text: &str) {
    assert!(parse(text).covers_service(ServiceName::iam()));
}

#[rstest]
#[case("iam:grant:sensitive")]
#[case("iam:grant:wildcard")]
#[case("iam:audit:read")]
#[case("iam:revoke:sessions")]
#[case("iam:revoke:global")]
#[case("iam:policy:resync")]
#[case("iam:route:anonymous")]
fn a_key_without_a_service_segment_covers_no_service(#[case] text: &str) {
    assert!(!parse(text).covers_service(&service("core")));
}

#[rstest]
#[case("iam:grant:*", "iam:grant:core", true)]
#[case("iam:grant:*", "iam:grant:iam", true)]
#[case("iam:grant:*", "iam:grant:*", true)]
#[case("iam:grant:core", "iam:grant:core", true)]
#[case("iam:grant:core", "iam:grant:other", false)]
#[case("iam:grant:core", "iam:grant:*", false)]
#[case("iam:grant:*", "iam:grant:sensitive", false)]
#[case("iam:grant:*", "iam:spec:core", false)]
#[case("iam:validate:*", "iam:validate:core", true)]
#[case("iam:validate:*", "iam:grant:core", false)]
#[case("iam:spec:*", "iam:spec:core", true)]
#[case("iam:spec:*", "iam:spec:iam", false)]
#[case("iam:spec:*", "iam:route:core", false)]
#[case("iam:route:*", "iam:route:core", true)]
#[case("iam:route:*", "iam:route:iam", false)]
#[case("iam:route:*", "iam:route:anonymous", false)]
#[case("iam:route:*", "iam:validate:core", false)]
#[case("iam:audit:read", "iam:audit:read", true)]
#[case("iam:audit:read", "iam:revoke:sessions", false)]
fn a_held_key_covers_a_required_key(
    #[case] held: &str,
    #[case] required: &str,
    #[case] expected: bool,
) {
    assert_eq!(parse(held).covers(&parse(required)), expected);
}

#[test]
fn a_service_scope_reports_its_service() {
    assert_eq!(on("core").service(), Some(&service("core")));
    assert_eq!(ServiceScope::All.service(), None);
}
