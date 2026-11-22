use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{
    AssignedRole, PrivilegedRoleAssigned, UserRoleAssigned, UserRoleRevoked, UserRoleUpdated,
};
use super::{
    PrivilegedGrants, RevocationCause, UserRole, UserRoleAssignment, UserRoleParts, UserRoleStamp,
};
use crate::error::{InvalidIamValue, InvalidUserRole, UserRoleChangeRefused, VersionConflict};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{ProjectId, RoleId, UserRoleId};
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_name::RoleName;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

const USER_ROLE: &str = "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706";
const OTHER_USER_ROLE: &str = "1c8f6e4d-3b2a-4091-9e7d-6c5b4a392817";
const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const OTHER_ROLE: &str = "8a2d3b5f-2e1c-4a6f-8b4d-3c7e9f1a2b3c";
const PROJECT: &str = "5e4d3c2b-1a09-4f8e-a7d6-c5b4a3928170";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const SUBJECT: &str = "9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const ALERT: &str = "01890a5d-ac96-774b-bcce-b302099a8058";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn stamp(seconds: u64) -> UserRoleStamp {
    UserRoleStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: actor(),
        occurred_at: at(seconds),
    }
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn subject() -> SubjectRef {
    SubjectRef::user(Uuid::parse(SUBJECT).unwrap())
}

fn project_scope() -> AssignmentScope {
    AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
}

fn role_name() -> RoleName {
    RoleName::new("Billing".to_owned()).unwrap()
}

fn assignment(expires_at: Option<SystemTime>) -> UserRoleAssignment {
    UserRoleAssignment {
        id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject: subject(),
        role_id: RoleId::parse(ROLE).unwrap(),
        role_name: role_name(),
        scope: project_scope(),
        expires_at,
        privileged: None,
    }
}

fn assigned_role() -> AssignedRole {
    AssignedRole {
        subject: subject(),
        role_id: RoleId::parse(ROLE).unwrap(),
        role_name: role_name(),
        scope: project_scope(),
    }
}

fn parts(current: i64) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject: subject(),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: project_scope(),
        expires_at: Some(AssignmentExpiry::restore(at(500))),
        version: version(current),
        created_by: actor(),
        created_at: at(10),
        updated_at: at(20),
        revoked_at: None,
    }
}

fn revoked(current: i64) -> UserRoleParts {
    UserRoleParts {
        revoked_at: Some(at(30)),
        ..parts(current)
    }
}

/// The single event the assignment recorded, downcast to its type.
fn single_event<E: DomainEvent + Clone>(user_role: &mut UserRole) -> E {
    let events = user_role.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[test]
fn an_assignment_starts_at_version_one_and_records_user_role_assigned() {
    let mut user_role = UserRole::assign(assignment(Some(at(200))), stamp(100)).unwrap();

    assert_eq!(
        user_role.parts(),
        &UserRoleParts {
            id: UserRoleId::parse(USER_ROLE).unwrap(),
            subject: subject(),
            role_id: RoleId::parse(ROLE).unwrap(),
            scope: project_scope(),
            expires_at: Some(AssignmentExpiry::restore(at(200))),
            version: EntityVersion::INITIAL,
            created_by: actor(),
            created_at: at(100),
            updated_at: at(100),
            revoked_at: None,
        }
    );
    assert_eq!(
        single_event::<UserRoleAssigned>(&mut user_role),
        UserRoleAssigned {
            event_id: Uuid::parse(EVENT).unwrap(),
            user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
            version: EntityVersion::INITIAL,
            role: assigned_role(),
            expires_at: Some(AssignmentExpiry::restore(at(200))),
            actor: actor(),
            occurred_at: at(100),
        }
    );
}

#[test]
fn an_assignment_without_an_expiry_never_expires() {
    let user_role = UserRole::assign(assignment(None), stamp(100)).unwrap();

    assert_eq!(user_role.parts().expires_at, None);
    assert!(user_role.parts().is_active_at(at(u64::from(u32::MAX))));
}

#[rstest]
#[case::now(100)]
#[case::past(99)]
fn an_assignment_whose_expiry_is_not_in_the_future_is_refused_at_expires_at(#[case] seconds: u64) {
    let refused = UserRole::assign(assignment(Some(at(seconds))), stamp(100)).unwrap_err();

    assert_eq!(refused, InvalidUserRole::ExpiryNotInFuture);
    assert_eq!(refused.property_path(), "expiresAt");
}

#[test]
fn a_privileged_role_also_records_the_security_alert() {
    let keys = vec![
        PermissionGrant::parse("iam:audit:read").unwrap(),
        PermissionGrant::parse("rest:billing:*").unwrap(),
    ];
    let mut user_role = UserRole::assign(
        UserRoleAssignment {
            privileged: Some(PrivilegedGrants {
                event_id: Uuid::parse(ALERT).unwrap(),
                keys: keys.clone(),
            }),
            ..assignment(None)
        },
        stamp(100),
    )
    .unwrap();

    let events = user_role.pull_domain_events();
    assert_eq!(events.len(), 2);
    let first: &dyn Any = events[0].as_ref();
    let second: &dyn Any = events[1].as_ref();
    assert!(first.downcast_ref::<UserRoleAssigned>().is_some());
    assert_eq!(
        second.downcast_ref::<PrivilegedRoleAssigned>().unwrap(),
        &PrivilegedRoleAssigned {
            event_id: Uuid::parse(ALERT).unwrap(),
            user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
            version: EntityVersion::INITIAL,
            role: assigned_role(),
            expires_at: None,
            privileged_keys: keys,
            actor: actor(),
            occurred_at: at(100),
        }
    );
}

#[test]
fn a_restored_assignment_records_nothing() {
    let mut user_role = UserRole::restore(parts(3));

    assert_eq!(user_role.parts(), &parts(3));
    assert!(user_role.pull_domain_events().is_empty());
}

#[rstest]
#[case::extend(Some(900))]
#[case::shorten(Some(101))]
#[case::clear(None)]
fn the_expiry_changes_and_records_user_role_updated(#[case] seconds: Option<u64>) {
    let mut user_role = UserRole::restore(parts(3));
    let expires_at = seconds.map(at);

    user_role
        .change_expiry(Some(version(3)), expires_at, stamp(100))
        .unwrap();

    let expiry = expires_at.map(AssignmentExpiry::restore);
    assert_eq!(user_role.parts().expires_at, expiry);
    assert_eq!(user_role.parts().version, version(4));
    assert_eq!(user_role.parts().updated_at, at(100));
    assert_eq!(user_role.parts().created_at, at(10));
    assert_eq!(
        single_event::<UserRoleUpdated>(&mut user_role),
        UserRoleUpdated {
            event_id: Uuid::parse(EVENT).unwrap(),
            user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
            version: version(4),
            subject: subject(),
            expires_at: expiry,
            actor: actor(),
            occurred_at: at(100),
        }
    );
}

#[rstest]
#[case::now(100)]
#[case::past(50)]
fn an_expiry_change_that_is_not_in_the_future_is_refused_at_expires_at(#[case] seconds: u64) {
    let mut user_role = UserRole::restore(parts(3));

    let refused = user_role
        .change_expiry(Some(version(3)), Some(at(seconds)), stamp(100))
        .unwrap_err();

    assert_eq!(
        refused,
        UserRoleChangeRefused::Invalid(InvalidUserRole::ExpiryNotInFuture)
    );
    let UserRoleChangeRefused::Invalid(invalid) = refused else {
        panic!("an invalid expiry");
    };
    assert_eq!(invalid.property_path(), "expiresAt");
    assert_eq!(user_role.parts(), &parts(3));
    assert!(user_role.pull_domain_events().is_empty());
}

#[rstest]
#[case::missing(None, UserRoleChangeRefused::Version(VersionConflict::Missing))]
#[case::stale(
    Some(2),
    UserRoleChangeRefused::Version(VersionConflict::Stale {
        expected: EntityVersion::new(2).unwrap(),
        current: EntityVersion::new(3).unwrap(),
    })
)]
fn a_change_without_the_current_version_is_refused(
    #[case] expected: Option<i64>,
    #[case] refusal: UserRoleChangeRefused,
) {
    let expected = expected.map(version);
    let mut user_role = UserRole::restore(parts(3));

    assert_eq!(
        user_role.change_expiry(expected, None, stamp(100)),
        Err(refusal)
    );
    assert_eq!(
        user_role.revoke(expected, role_name(), RevocationCause::Revoked, stamp(100)),
        Err(refusal)
    );
    assert_eq!(user_role.parts(), &parts(3));
    assert!(user_role.pull_domain_events().is_empty());
}

#[test]
fn a_revoked_assignment_refuses_every_change() {
    let mut user_role = UserRole::restore(revoked(4));

    assert_eq!(
        user_role.change_expiry(Some(version(4)), None, stamp(100)),
        Err(UserRoleChangeRefused::Revoked)
    );
    assert_eq!(
        user_role.revoke(
            Some(version(4)),
            role_name(),
            RevocationCause::Revoked,
            stamp(100)
        ),
        Err(UserRoleChangeRefused::Revoked)
    );
    assert_eq!(user_role.parts(), &revoked(4));
    assert!(user_role.pull_domain_events().is_empty());
}

#[test]
fn a_version_that_cannot_grow_refuses_the_change() {
    let mut user_role = UserRole::restore(parts(i64::MAX));

    assert_eq!(
        user_role.change_expiry(Some(version(i64::MAX)), None, stamp(100)),
        Err(UserRoleChangeRefused::Range(
            InvalidIamValue::EntityVersionRange
        ))
    );
}

#[rstest]
#[case(RevocationCause::Revoked)]
#[case(RevocationCause::RoleDeleted)]
#[case(RevocationCause::UserDeleted)]
fn a_revocation_marks_the_assignment_and_records_the_cause(#[case] cause: RevocationCause) {
    let mut user_role = UserRole::restore(parts(3));

    user_role
        .revoke(Some(version(3)), role_name(), cause, stamp(100))
        .unwrap();

    assert_eq!(user_role.parts().revoked_at, Some(at(100)));
    assert_eq!(user_role.parts().version, version(4));
    assert_eq!(user_role.parts().updated_at, at(100));
    assert!(user_role.parts().is_revoked());
    assert_eq!(
        single_event::<UserRoleRevoked>(&mut user_role),
        UserRoleRevoked {
            event_id: Uuid::parse(EVENT).unwrap(),
            user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
            version: version(4),
            role: assigned_role(),
            cause,
            actor: actor(),
            occurred_at: at(100),
        }
    );
}

#[test]
fn the_causes_have_stable_text_forms() {
    assert_eq!(RevocationCause::Revoked.as_str(), "revoked");
    assert_eq!(RevocationCause::RoleDeleted.as_str(), "role_deleted");
    assert_eq!(RevocationCause::UserDeleted.as_str(), "user_deleted");
}

#[rstest]
#[case::before_expiry(499, true)]
#[case::at_expiry(500, false)]
#[case::after_expiry(501, false)]
fn an_assignment_is_active_until_it_expires(#[case] now: u64, #[case] active: bool) {
    assert_eq!(parts(1).is_active_at(at(now)), active);
}

#[test]
fn a_revoked_assignment_is_never_active() {
    assert!(!revoked(2).is_active_at(at(0)));
    assert!(
        !UserRoleParts {
            expires_at: None,
            ..revoked(2)
        }
        .is_active_at(at(0))
    );
}

#[test]
fn an_assignment_that_is_not_revoked_duplicates_one_with_the_same_triple() {
    let stored = parts(1);
    let again = UserRoleParts {
        id: UserRoleId::parse(OTHER_USER_ROLE).unwrap(),
        expires_at: None,
        ..parts(1)
    };

    assert!(again.duplicates(&stored));
    assert!(stored.duplicates(&again));
}

#[test]
fn an_expired_assignment_still_holds_its_triple() {
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(1))),
        ..parts(1)
    };
    let again = UserRoleParts {
        id: UserRoleId::parse(OTHER_USER_ROLE).unwrap(),
        ..parts(1)
    };

    assert!(again.duplicates(&expired));
}

#[test]
fn a_revoked_assignment_frees_its_triple() {
    let again = UserRoleParts {
        id: UserRoleId::parse(OTHER_USER_ROLE).unwrap(),
        ..parts(1)
    };

    assert!(!again.duplicates(&revoked(2)));
    assert!(!revoked(2).duplicates(&again));
}

#[rstest]
#[case::other_subject(UserRoleParts {
    subject: SubjectRef::service(ServiceName::new("billing-service").unwrap()),
    ..parts(1)
})]
#[case::other_role(UserRoleParts { role_id: RoleId::parse(OTHER_ROLE).unwrap(), ..parts(1) })]
#[case::other_scope(UserRoleParts { scope: AssignmentScope::Global, ..parts(1) })]
fn an_assignment_with_another_triple_is_no_duplicate(#[case] other: UserRoleParts) {
    assert!(!other.duplicates(&parts(1)));
    assert!(!parts(1).duplicates(&other));
}
