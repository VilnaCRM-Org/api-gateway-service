use std::collections::BTreeMap;
use std::time::SystemTime;

use rstest::rstest;

use super::{RouteScopeGuard, RouteScopeRefused};
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::RoleAssignment;
use crate::policy::subject_policy::SubjectPolicy;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::RoleId;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;
use crate::value_object::service_name::ServiceName;

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

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

#[rstest]
#[case::service_key(&["iam:route:core"], true)]
#[case::global_key(&["iam:route:*"], true)]
#[case::other_service_key(&["iam:route:billing"], false)]
#[case::anonymous_key_only(&["iam:route:anonymous"], false)]
#[case::nothing(&[], false)]
fn a_route_of_a_service_needs_its_key_or_the_global_key(
    #[case] grants: &[&str],
    #[case] allowed: bool,
) {
    let core = service("core");

    let result = RouteScopeGuard::check_route(&held(grants), &core, false, &core);

    if allowed {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result, Err(RouteScopeRefused::Missing { service: core }));
    }
}

#[rstest]
#[case::service_key(&["iam:route:core"], true)]
#[case::global_key(&["iam:route:*"], true)]
#[case::nothing(&[], false)]
fn an_upstream_of_a_service_needs_the_same_keys(#[case] grants: &[&str], #[case] allowed: bool) {
    let result = RouteScopeGuard::check_upstream(&held(grants), &service("core"), false);

    assert_eq!(result.is_ok(), allowed);
}

#[test]
fn nobody_may_change_an_iam_entry() {
    let iam = service("iam");
    let everything = held(&["iam:route:*", "iam:route:anonymous"]);

    assert_eq!(
        RouteScopeGuard::check_route(&everything, &iam, false, &iam),
        Err(RouteScopeRefused::IamService)
    );
    assert_eq!(
        RouteScopeGuard::check_upstream(&everything, &iam, false),
        Err(RouteScopeRefused::IamService)
    );
}

#[test]
fn nobody_may_change_a_system_entry() {
    let core = service("core");
    let everything = held(&["iam:route:*", "iam:route:core"]);

    assert_eq!(
        RouteScopeGuard::check_route(&everything, &core, true, &core),
        Err(RouteScopeRefused::SystemEntry)
    );
    assert_eq!(
        RouteScopeGuard::check_upstream(&everything, &core, true),
        Err(RouteScopeRefused::SystemEntry)
    );
}

#[test]
fn a_route_must_serve_the_service_of_its_upstream() {
    let route = service("core");
    let upstream = service("billing");

    let result = RouteScopeGuard::check_route(&held(&["iam:route:*"]), &route, false, &upstream);

    assert_eq!(
        result,
        Err(RouteScopeRefused::ServiceMismatch { route, upstream })
    );
}

#[test]
fn refusals_have_codes_and_messages() {
    let core = service("core");
    let mismatch = RouteScopeRefused::ServiceMismatch {
        route: core.clone(),
        upstream: service("billing"),
    };
    let missing = RouteScopeRefused::Missing { service: core };

    assert_eq!(RouteScopeRefused::IamService.code(), "system_entry");
    assert_eq!(RouteScopeRefused::SystemEntry.code(), "system_entry");
    assert_eq!(mismatch.code(), "service_mismatch");
    assert_eq!(missing.code(), "forbidden");
    assert!(missing.to_string().contains("iam:route:core"));
    assert!(mismatch.to_string().contains("billing"));
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
#[case::service_key(&["iam:route:core"], true)]
#[case::global_key(&["iam:route:*"], true)]
#[case::other_service_key(&["iam:route:billing"], false)]
#[case::anonymous_key_only(&["iam:route:anonymous"], false)]
#[case::nothing(&[], false)]
fn the_policy_of_an_actor_needs_the_key_of_the_service_or_the_global_key(
    #[case] grants: &[&str],
    #[case] allowed: bool,
) {
    let core = service("core");

    let result = RouteScopeGuard::check_policy(
        &policy(grants, AssignmentScope::Global),
        SystemTime::UNIX_EPOCH,
        &core,
    );

    if allowed {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result, Err(RouteScopeRefused::Missing { service: core }));
    }
}

#[test]
fn the_global_key_never_covers_the_iam_service_in_a_policy() {
    let iam = service("iam");

    let result = RouteScopeGuard::check_policy(
        &policy(&["iam:route:*"], AssignmentScope::Global),
        SystemTime::UNIX_EPOCH,
        &iam,
    );

    assert_eq!(result, Err(RouteScopeRefused::Missing { service: iam }));
}

#[test]
fn the_entries_nobody_may_change_are_named_without_a_policy() {
    let core = service("core");

    assert_eq!(
        RouteScopeGuard::check_changeable(&service("iam"), false),
        Err(RouteScopeRefused::IamService)
    );
    assert_eq!(
        RouteScopeGuard::check_changeable(&core, true),
        Err(RouteScopeRefused::SystemEntry)
    );
    assert_eq!(RouteScopeGuard::check_changeable(&core, false), Ok(()));
}
