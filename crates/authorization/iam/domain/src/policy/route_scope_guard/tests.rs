use rstest::rstest;

use super::{RouteScopeGuard, RouteScopeRefused};
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
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
