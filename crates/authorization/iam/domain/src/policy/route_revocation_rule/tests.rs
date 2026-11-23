use rstest::rstest;

use super::{RouteChangeClass, RouteRevocationRule};
use crate::route::fields::RouteFields;
use crate::route::fixtures::draft;
use crate::route::settings::{EnforcementMode, RouteFlag, RouteFlags};
use crate::value_object::http_method::HttpMethod;

fn route(anonymous: bool, enforcement: EnforcementMode, request_timeout_ms: i64) -> RouteFields {
    let mut route = draft("api.example.com", "/api/orders", &[HttpMethod::Get]);
    route.flags = RouteFlags::default().with(RouteFlag::Anonymous, anonymous);
    route.enforcement = enforcement;
    route.request_timeout_ms = request_timeout_ms;
    RouteFields::new(&route).unwrap()
}

#[rstest]
#[case::clearing_anonymous(
    route(true, EnforcementMode::Enforce, 1_000),
    route(false, EnforcementMode::Enforce, 1_000),
    RouteChangeClass::Revocation
)]
#[case::audit_to_enforce(
    route(false, EnforcementMode::Audit, 1_000),
    route(false, EnforcementMode::Enforce, 1_000),
    RouteChangeClass::Revocation
)]
#[case::only_a_timeout(
    route(false, EnforcementMode::Enforce, 1_000),
    route(false, EnforcementMode::Enforce, 2_000),
    RouteChangeClass::Standard
)]
#[case::setting_anonymous(
    route(false, EnforcementMode::Enforce, 1_000),
    route(true, EnforcementMode::Enforce, 1_000),
    RouteChangeClass::Standard
)]
#[case::enforce_to_audit(
    route(false, EnforcementMode::Enforce, 1_000),
    route(false, EnforcementMode::Audit, 1_000),
    RouteChangeClass::Standard
)]
#[case::staying_anonymous(
    route(true, EnforcementMode::Audit, 1_000),
    route(true, EnforcementMode::Audit, 2_000),
    RouteChangeClass::Standard
)]
fn updates_are_classified_by_what_they_take_away(
    #[case] before: RouteFields,
    #[case] after: RouteFields,
    #[case] class: RouteChangeClass,
) {
    assert_eq!(RouteRevocationRule::classify_update(&before, &after), class);
}

#[test]
fn a_deletion_is_a_revocation() {
    assert_eq!(
        RouteRevocationRule::classify_delete(),
        RouteChangeClass::Revocation
    );
}
