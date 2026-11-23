use rstest::rstest;

use super::{AnonymousRouteGuard, AnonymousRouteRefused};
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::route::fields::RouteFields;
use crate::route::fixtures::draft;
use crate::route::settings::{EnforcementMode, RouteFlag, RouteFlags};
use crate::value_object::http_method::HttpMethod;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;

fn held(grants: &[&str]) -> CompiledRoleSet {
    CompiledRoleSet::from_active(
        &PermissionGrantSet::new(
            grants
                .iter()
                .map(|grant| PermissionGrant::parse(grant).unwrap()),
        )
        .unwrap(),
    )
}

fn holder() -> CompiledRoleSet {
    held(&["iam:route:anonymous"])
}

fn route(anonymous: bool, enforcement: EnforcementMode) -> RouteFields {
    let mut route = draft("api.example.com", "/api/orders", &[HttpMethod::Get]);
    route.flags = RouteFlags::default().with(RouteFlag::Anonymous, anonymous);
    route.enforcement = enforcement;
    RouteFields::new(&route).unwrap()
}

#[rstest]
#[case::anonymous(true, EnforcementMode::Enforce)]
#[case::audit(false, EnforcementMode::Audit)]
#[case::both(true, EnforcementMode::Audit)]
fn creating_a_route_that_needs_the_key_is_for_its_holder_only(
    #[case] anonymous: bool,
    #[case] enforcement: EnforcementMode,
) {
    let fields = route(anonymous, enforcement);

    assert_eq!(
        AnonymousRouteGuard::check_create(&holder(), &fields),
        Ok(())
    );
    assert_eq!(
        AnonymousRouteGuard::check_create(&held(&["iam:route:*"]), &fields),
        Err(AnonymousRouteRefused)
    );
    assert_eq!(
        AnonymousRouteGuard::check_create(&CompiledRoleSet::default(), &fields),
        Err(AnonymousRouteRefused)
    );
}

#[test]
fn creating_a_protected_enforced_route_needs_no_key() {
    let fields = route(false, EnforcementMode::Enforce);

    assert_eq!(
        AnonymousRouteGuard::check_create(&CompiledRoleSet::default(), &fields),
        Ok(())
    );
}

#[rstest]
#[case::set_anonymous(
    route(false, EnforcementMode::Enforce),
    route(true, EnforcementMode::Enforce)
)]
#[case::clear_anonymous(
    route(true, EnforcementMode::Enforce),
    route(false, EnforcementMode::Enforce)
)]
#[case::set_audit(
    route(false, EnforcementMode::Enforce),
    route(false, EnforcementMode::Audit)
)]
#[case::clear_audit(
    route(false, EnforcementMode::Audit),
    route(false, EnforcementMode::Enforce)
)]
fn changing_either_flag_is_for_the_holder_only(
    #[case] before: RouteFields,
    #[case] after: RouteFields,
) {
    assert_eq!(
        AnonymousRouteGuard::check_update(&holder(), &before, &after),
        Ok(())
    );
    assert_eq!(
        AnonymousRouteGuard::check_update(&CompiledRoleSet::default(), &before, &after),
        Err(AnonymousRouteRefused)
    );
}

#[test]
fn an_update_that_leaves_both_flags_alone_needs_no_key() {
    let before = route(true, EnforcementMode::Audit);
    let mut timeout = draft("api.example.com", "/api/orders", &[HttpMethod::Get]);
    timeout.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);
    timeout.enforcement = EnforcementMode::Audit;
    timeout.request_timeout_ms = 1;
    let after = RouteFields::new(&timeout).unwrap();

    assert_eq!(
        AnonymousRouteGuard::check_update(&CompiledRoleSet::default(), &before, &after),
        Ok(())
    );
}

#[test]
fn the_refusal_has_a_code_and_a_message() {
    assert_eq!(AnonymousRouteRefused::CODE, "anonymous_route_forbidden");
    assert!(
        AnonymousRouteRefused
            .to_string()
            .contains("iam:route:anonymous")
    );
}
