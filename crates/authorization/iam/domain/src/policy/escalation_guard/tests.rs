use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rstest::rstest;

use super::{EscalationDenied, EscalationGuard, GrantedKey, GrantedKind};
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
use crate::value_object::subject::SubjectRef;

const ROLE: &str = "0198d1a0-0000-7000-8000-000000000001";
const PROJECT: &str = "0198d1a0-0000-7000-8000-0000000000aa";
const USER: &str = "0198d1a0-0000-7000-8000-0000000000b1";
const OTHER: &str = "0198d1a0-0000-7000-8000-0000000000b2";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn epoch() -> PolicyEpoch {
    PolicyEpoch::new(
        PolicyVersion::new(1).unwrap(),
        PolicyDigestValue::new(&[1; PolicyDigestValue::LENGTH]).unwrap(),
        LogEpoch::new(0).unwrap(),
        RelayEpoch::new(0).unwrap(),
        0,
    )
    .unwrap()
}

/// The policy of an actor that holds `grants` through one assignment in `scope`.
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
    SubjectPolicy::new(
        epoch(),
        vec![RoleAssignment::new(role, scope, None)],
        BTreeMap::from([(role, set)]),
    )
}

fn global(grants: &[&str]) -> SubjectPolicy {
    policy(grants, AssignmentScope::Global)
}

fn plain(name: &str) -> GrantedKey {
    GrantedKey::new(service(name), GrantedKind::Plain)
}

fn sensitive(name: &str) -> GrantedKey {
    GrantedKey::new(service(name), GrantedKind::Sensitive)
}

fn wildcard(name: &str) -> GrantedKey {
    GrantedKey::new(service(name), GrantedKind::Wildcard)
}

fn reserved(key: &str) -> ReservedPermission {
    ReservedPermission::parse(key).unwrap()
}

fn missing(key: &str) -> Result<(), EscalationDenied> {
    Err(EscalationDenied::Missing { key: reserved(key) })
}

#[test]
fn a_grant_is_reduced_to_its_service_and_what_it_needs_besides() {
    let exact = PermissionGrant::parse("rest:core:GET /users").unwrap();
    let pattern = PermissionGrant::parse("rest:core:*").unwrap();
    let reserved = PermissionGrant::parse("iam:audit:read").unwrap();

    assert_eq!(GrantedKey::of(&exact, false), plain("core"));
    assert_eq!(GrantedKey::of(&exact, true), sensitive("core"));
    assert_eq!(GrantedKey::of(&pattern, true), wildcard("core"));
    assert_eq!(GrantedKey::of(&reserved, false), plain("iam"));
    assert_eq!(plain("core").service(), &service("core"));
    assert_eq!(sensitive("core").kind(), GrantedKind::Sensitive);
}

#[test]
fn the_grants_need_each_key_once_in_order() {
    let required = EscalationGuard::required(&[
        plain("core"),
        sensitive("core"),
        wildcard("payment"),
        plain("core"),
    ]);

    let texts: Vec<String> = required.iter().map(ToString::to_string).collect();
    assert_eq!(
        texts,
        [
            "iam:grant:core",
            "iam:grant:sensitive",
            "iam:grant:payment",
            "iam:grant:wildcard"
        ]
    );
}

#[rstest]
#[case::service_key(&["iam:grant:core"], true)]
#[case::global_key(&["iam:grant:*"], true)]
#[case::other_service(&["iam:grant:payment"], false)]
#[case::sensitive_only(&["iam:grant:sensitive"], false)]
#[case::nothing(&[], false)]
fn a_plain_key_needs_the_grant_key_of_its_service_or_the_global_one(
    #[case] held: &[&str],
    #[case] allowed: bool,
) {
    let result = EscalationGuard::check(&global(held), now(), &[plain("core")]);

    if allowed {
        assert_eq!(result, Ok(()));
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn a_grant_key_held_only_at_project_scope_grants_nothing() {
    let project = ProjectId::parse(PROJECT).unwrap();
    let held = policy(&["iam:grant:core"], AssignmentScope::Project(project));

    let result = EscalationGuard::check(&held, now(), &[plain("core")]);

    assert_eq!(result, missing("iam:grant:core"));
}

#[test]
fn a_sensitive_key_also_needs_the_sensitive_grant_key() {
    let without = global(&["iam:grant:core"]);
    let with = global(&["iam:grant:core", "iam:grant:sensitive"]);

    assert_eq!(
        EscalationGuard::check(&without, now(), &[sensitive("core")]),
        missing("iam:grant:sensitive")
    );
    assert_eq!(
        EscalationGuard::check(&with, now(), &[sensitive("core")]),
        Ok(())
    );
}

#[test]
fn a_wildcard_also_needs_the_wildcard_grant_key() {
    let without = global(&["iam:grant:*", "iam:grant:sensitive"]);
    let with = global(&["iam:grant:*", "iam:grant:wildcard"]);

    assert_eq!(
        EscalationGuard::check(&without, now(), &[wildcard("core")]),
        missing("iam:grant:wildcard")
    );
    assert_eq!(
        EscalationGuard::check(&with, now(), &[wildcard("core")]),
        Ok(())
    );
}

#[test]
fn a_reserved_key_belongs_to_iam_and_needs_the_iam_grant_key() {
    let core_only = global(&["iam:grant:core"]);
    let everything = global(&["iam:grant:*"]);
    let iam_key = [GrantedKey::of(
        &PermissionGrant::parse("iam:audit:read").unwrap(),
        false,
    )];

    assert_eq!(
        EscalationGuard::check(&core_only, now(), &iam_key),
        missing("iam:grant:iam")
    );
    assert_eq!(EscalationGuard::check(&everything, now(), &iam_key), Ok(()));
}

#[test]
fn an_empty_grant_list_needs_nothing() {
    assert_eq!(EscalationGuard::check(&global(&[]), now(), &[]), Ok(()));
}

#[test]
fn the_first_missing_key_is_reported() {
    let result = EscalationGuard::check(
        &global(&["iam:grant:core"]),
        now(),
        &[plain("core"), plain("payment"), wildcard("payment")],
    );

    assert_eq!(result, missing("iam:grant:payment"));
}

#[test]
fn an_actor_cannot_act_on_its_own_assignment() {
    let actor = SubjectRef::user(shared_domain::Uuid::parse(USER).unwrap());
    let other = SubjectRef::user(shared_domain::Uuid::parse(OTHER).unwrap());

    assert_eq!(
        EscalationGuard::check_subject(&actor, &actor),
        Err(EscalationDenied::OwnAssignment)
    );
    assert_eq!(EscalationGuard::check_subject(&actor, &other), Ok(()));
}

#[test]
fn a_refusal_names_its_code_and_what_is_missing() {
    assert_eq!(EscalationDenied::CODE, "escalation.denied");
    assert!(
        EscalationDenied::OwnAssignment
            .to_string()
            .contains("its own assignment")
    );
    assert!(
        missing("iam:grant:core")
            .unwrap_err()
            .to_string()
            .contains("iam:grant:core")
    );
}
