use std::collections::BTreeMap;
use std::time::SystemTime;

use rstest::rstest;

use super::{AnonymousRouteGuard, AnonymousRouteRefused};
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::RoleAssignment;
use crate::policy::subject_policy::SubjectPolicy;
use crate::route::fields::RouteFields;
use crate::route::fixtures::draft;
use crate::route::settings::{EnforcementMode, RouteFlag, RouteFlags};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::RoleId;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

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

const ROLE: &str = "0198d1a0-0000-7000-8000-000000000001";

fn policy(grants: &[&str], scope: AssignmentScope) -> SubjectPolicy {
    let role = RoleId::parse(ROLE).unwrap();
    let epoch = PolicyEpoch::new(
        PolicyVersion::new(1).unwrap(),
        PolicyDigestValue::new(&[1; PolicyDigestValue::LENGTH]).unwrap(),
        LogEpoch::new(0).unwrap(),
        RelayEpoch::new(0).unwrap(),
        0,
    )
    .unwrap();
    SubjectPolicy::new(
        epoch,
        vec![RoleAssignment::new(role, scope, None)],
        BTreeMap::from([(role, held(grants))]),
    )
}

#[rstest]
#[case::holder(&["iam:route:anonymous"], AssignmentScope::Global, true)]
#[case::route_key_only(&["iam:route:*"], AssignmentScope::Global, false)]
#[case::nothing(&[], AssignmentScope::Global, false)]
fn the_policy_of_an_actor_needs_the_anonymous_key(
    #[case] grants: &[&str],
    #[case] scope: AssignmentScope,
    #[case] allowed: bool,
) {
    let result = AnonymousRouteGuard::check_policy(&policy(grants, scope), SystemTime::UNIX_EPOCH);

    if allowed {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result, Err(AnonymousRouteRefused));
    }
}

#[rstest]
#[case::anonymous(true, EnforcementMode::Enforce, true)]
#[case::audit(false, EnforcementMode::Audit, true)]
#[case::plain(false, EnforcementMode::Enforce, false)]
fn a_creation_needs_the_key_only_for_an_anonymous_or_audit_only_route(
    #[case] anonymous: bool,
    #[case] enforcement: EnforcementMode,
    #[case] needed: bool,
) {
    assert_eq!(
        AnonymousRouteGuard::needs_key_on_create(&route(anonymous, enforcement)),
        needed
    );
}

#[rstest]
#[case::set_anonymous(false, EnforcementMode::Enforce, true, EnforcementMode::Enforce, true)]
#[case::set_audit(false, EnforcementMode::Enforce, false, EnforcementMode::Audit, true)]
#[case::unchanged(true, EnforcementMode::Audit, true, EnforcementMode::Audit, false)]
fn an_update_needs_the_key_only_when_it_changes_a_flag(
    #[case] before_anonymous: bool,
    #[case] before_enforcement: EnforcementMode,
    #[case] after_anonymous: bool,
    #[case] after_enforcement: EnforcementMode,
    #[case] needed: bool,
) {
    let before = route(before_anonymous, before_enforcement);
    let after = route(after_anonymous, after_enforcement);

    assert_eq!(
        AnonymousRouteGuard::needs_key_on_update(&before, &after),
        needed
    );
}
