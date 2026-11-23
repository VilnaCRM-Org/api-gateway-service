use std::time::{Duration, SystemTime};

use super::{LastAdministratorGuard, LastAdministratorRefused};
use crate::role::RoleParts;
use crate::user_role::UserRoleParts;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{ProjectId, RoleId, UserRoleId};
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::SubjectRef;
use shared_domain::Uuid;

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const FIRST: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";
const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn later(hours: u64) -> SystemTime {
    now().checked_add(Duration::from_hours(hours)).unwrap()
}

fn role(name: &str, kind: RoleKind) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new(name.to_owned()).unwrap(),
        description: None,
        kind,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn admin_role() -> RoleParts {
    role("iam-platform-admin", RoleKind::System)
}

fn assignment(id: &str) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(id).unwrap(),
        subject: SubjectRef::user(Uuid::parse(USER).unwrap()),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: None,
        version: EntityVersion::INITIAL,
        created_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn guard(assignment: &UserRoleParts) -> LastAdministratorGuard {
    LastAdministratorGuard::of(&admin_role(), assignment, now())
}

#[test]
fn an_active_global_assignment_of_the_administrator_role_is_protected() {
    assert!(guard(&assignment(FIRST)).protects());
}

#[test]
fn an_assignment_of_another_role_or_kind_is_not_protected() {
    let first = assignment(FIRST);

    let custom = role("iam-platform-admin", RoleKind::Custom);
    let other = role("Billing", RoleKind::System);

    assert!(!LastAdministratorGuard::of(&custom, &first, now()).protects());
    assert!(!LastAdministratorGuard::of(&other, &first, now()).protects());
}

#[test]
fn a_project_scoped_revoked_or_expired_assignment_is_not_protected() {
    let project = UserRoleParts {
        scope: AssignmentScope::Project(
            ProjectId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890b0").unwrap(),
        ),
        ..assignment(FIRST)
    };
    let revoked = UserRoleParts {
        revoked_at: Some(now()),
        ..assignment(FIRST)
    };
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(now())),
        ..assignment(FIRST)
    };

    for unprotected in [project, revoked, expired] {
        assert!(!guard(&unprotected).protects(), "{unprotected:?}");
    }
}

#[test]
fn an_assignment_of_a_role_with_another_id_is_not_protected() {
    let foreign = UserRoleParts {
        role_id: RoleId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890b1").unwrap(),
        ..assignment(FIRST)
    };

    assert!(!guard(&foreign).protects());
}

#[test]
fn another_administrator_is_an_active_global_assignment_with_another_id() {
    let excluded = UserRoleId::parse(FIRST).unwrap();
    let revoked = UserRoleParts {
        revoked_at: Some(now()),
        ..assignment(SECOND)
    };

    assert!(LastAdministratorGuard::is_other_administrator(
        &assignment(SECOND),
        excluded,
        now()
    ));
    assert!(!LastAdministratorGuard::is_other_administrator(
        &assignment(FIRST),
        excluded,
        now()
    ));
    assert!(!LastAdministratorGuard::is_other_administrator(
        &revoked,
        excluded,
        now()
    ));
}

#[test]
fn the_last_administrator_cannot_be_revoked_but_one_of_two_can() {
    let guard = guard(&assignment(FIRST));

    assert_eq!(guard.check_revocation(0), Err(LastAdministratorRefused));
    assert_eq!(guard.check_revocation(1), Ok(()));
}

#[test]
fn an_unprotected_assignment_is_always_let_through() {
    let custom = role("Billing", RoleKind::Custom);
    let guard = LastAdministratorGuard::of(&custom, &assignment(FIRST), now());

    assert_eq!(guard.check_revocation(0), Ok(()));
    assert_eq!(guard.check_expiry(None, Some(later(1)), 0), Ok(()));
}

#[test]
fn an_earlier_expiry_of_the_last_administrator_is_refused() {
    let guard = guard(&assignment(FIRST));
    let current = Some(AssignmentExpiry::restore(later(10)));

    assert_eq!(
        guard.check_expiry(None, Some(later(1)), 0),
        Err(LastAdministratorRefused)
    );
    assert_eq!(
        guard.check_expiry(current, Some(later(1)), 0),
        Err(LastAdministratorRefused)
    );
}

#[test]
fn a_later_or_cleared_expiry_and_any_expiry_beside_another_administrator_are_let_through() {
    let guard = guard(&assignment(FIRST));
    let current = Some(AssignmentExpiry::restore(later(10)));

    assert_eq!(guard.check_expiry(current, Some(later(20)), 0), Ok(()));
    assert_eq!(guard.check_expiry(current, None, 0), Ok(()));
    assert_eq!(guard.check_expiry(None, None, 0), Ok(()));
    assert_eq!(guard.check_expiry(None, Some(later(1)), 1), Ok(()));
}

#[test]
fn the_refusal_has_a_code_and_a_message() {
    assert_eq!(LastAdministratorRefused::CODE, "last_administrator");
    assert!(LastAdministratorRefused.to_string().contains("last"));
}
