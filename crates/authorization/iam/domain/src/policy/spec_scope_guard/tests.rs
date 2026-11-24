use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rstest::rstest;

use super::{SpecScopeDenied, SpecScopeGuard};
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::RoleAssignment;
use crate::policy::subject_policy::SubjectPolicy;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::{ProjectId, RoleId};
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;
use crate::value_object::reserved_permission::ReservedPermission;
use crate::value_object::service_name::ServiceName;

const ROLE: &str = "0198d1a0-0000-7000-8000-000000000001";
const PROJECT: &str = "0198d1a0-0000-7000-8000-0000000000aa";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn policy(grants: &[&str], scope: AssignmentScope) -> SubjectPolicy {
    let role = RoleId::parse(ROLE).unwrap();
    let set = CompiledRoleSet::from_active(
        &PermissionGrantSet::new(
            grants
                .iter()
                .map(|grant| PermissionGrant::parse(grant).unwrap()),
        )
        .unwrap(),
    );
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
        BTreeMap::from([(role, set)]),
    )
}

fn reserved(key: &str) -> ReservedPermission {
    ReservedPermission::parse(key).unwrap()
}

fn denied(key: &str) -> Result<(), SpecScopeDenied> {
    Err(SpecScopeDenied { key: reserved(key) })
}

#[rstest]
#[case::own_service("core", &["iam:spec:core"], Ok(()))]
#[case::global_key("core", &["iam:spec:*"], Ok(()))]
#[case::other_service("payment", &["iam:spec:core"], denied("iam:spec:payment"))]
#[case::nothing("core", &[], denied("iam:spec:core"))]
#[case::global_key_never_covers_iam("iam", &["iam:spec:*"], denied("iam:spec:iam"))]
#[case::iam_key_covers_iam("iam", &["iam:spec:iam"], Ok(()))]
fn a_service_needs_its_spec_key_or_the_global_one_that_never_covers_iam(
    #[case] target: &str,
    #[case] held: &[&str],
    #[case] expected: Result<(), SpecScopeDenied>,
) {
    let result = SpecScopeGuard::check(
        &policy(held, AssignmentScope::Global),
        now(),
        &service(target),
        false,
    );

    assert_eq!(result, expected);
}

#[test]
fn a_spec_key_held_only_at_project_scope_changes_nothing() {
    let project = ProjectId::parse(PROJECT).unwrap();
    let held = policy(&["iam:spec:core"], AssignmentScope::Project(project));

    let result = SpecScopeGuard::check(&held, now(), &service("core"), false);

    assert_eq!(result, denied("iam:spec:core"));
}

#[test]
fn a_confirmed_flag_downgrade_also_needs_the_sensitive_grant_key() {
    let without = policy(&["iam:spec:core"], AssignmentScope::Global);
    let with = policy(
        &["iam:spec:core", "iam:grant:sensitive"],
        AssignmentScope::Global,
    );

    assert_eq!(
        SpecScopeGuard::check(&without, now(), &service("core"), true),
        denied("iam:grant:sensitive")
    );
    assert_eq!(
        SpecScopeGuard::check(&with, now(), &service("core"), true),
        Ok(())
    );
    assert_eq!(
        SpecScopeGuard::check(&without, now(), &service("core"), false),
        Ok(())
    );
}

#[test]
fn the_required_keys_follow_the_service_and_the_downgrade() {
    let plain: Vec<String> = SpecScopeGuard::required(&service("core"), false)
        .iter()
        .map(ToString::to_string)
        .collect();
    let downgrade: Vec<String> = SpecScopeGuard::required(&service("core"), true)
        .iter()
        .map(ToString::to_string)
        .collect();

    assert_eq!(plain, ["iam:spec:core"]);
    assert_eq!(downgrade, ["iam:spec:core", "iam:grant:sensitive"]);
}

#[test]
fn a_refusal_names_its_code_and_the_missing_key() {
    assert_eq!(SpecScopeDenied::CODE, "spec_scope.denied");
    assert!(
        denied("iam:spec:core")
            .unwrap_err()
            .to_string()
            .contains("iam:spec:core")
    );
}
