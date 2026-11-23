use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ADMINISTRATORS_LOCK, ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, EntityVersion,
    PermissionGrantSet, ProjectId, RoleId, RoleKind, RoleName, RoleParts, SubjectRef, UserRoleId,
    UserRoleParts,
};
use shared_domain::Uuid;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::startup_lock::FakeStartupLock;
use test_support::user_role::FakeUserRoleRepository;

use super::{AdministratorSafeguard, SafeguardPorts};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const FIRST: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";
const THIRD: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890b0";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn later(hours: u64) -> SystemTime {
    at().checked_add(Duration::from_hours(hours)).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
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

fn administrator_role() -> RoleParts {
    role("iam-platform-admin", RoleKind::System)
}

fn assignment(id: &str) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(id).unwrap(),
        subject: SubjectRef::user(Uuid::parse(id).unwrap()),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: None,
        version: EntityVersion::INITIAL,
        created_by: actor(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

struct Doubles {
    audit: Arc<FakeSecurityAuditLog>,
    lock: Arc<FakeStartupLock>,
}

fn safeguard(
    roles: FakeRoleRepository,
    user_roles: FakeUserRoleRepository,
) -> (AdministratorSafeguard, Doubles) {
    let doubles = Doubles {
        audit: Arc::new(FakeSecurityAuditLog::new()),
        lock: Arc::new(FakeStartupLock::new()),
    };
    let safeguard = AdministratorSafeguard::new(
        SafeguardPorts {
            roles: Arc::new(roles),
            user_roles: Arc::new(user_roles),
            audit_log: Arc::<FakeSecurityAuditLog>::clone(&doubles.audit),
            startup_lock: Arc::<FakeStartupLock>::clone(&doubles.lock),
        },
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    (safeguard, doubles)
}

fn administrators(assignments: Vec<UserRoleParts>) -> (AdministratorSafeguard, Doubles) {
    safeguard(
        FakeRoleRepository::holding(vec![administrator_role()]),
        FakeUserRoleRepository::holding(assignments),
    )
}

#[tokio::test]
async fn the_last_administrator_cannot_be_revoked_and_the_refusal_is_audited() {
    let (safeguard, doubles) = administrators(vec![assignment(FIRST)]);

    let error = safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
    let recorded = doubles.audit.recorded();
    assert_eq!(recorded.len(), 1);
    let audit = recorded[0].event().parts();
    assert_eq!(audit.action.as_str(), "user_role.revoke");
    assert_eq!(audit.outcome, AuditOutcome::Rejected);
    assert_eq!(audit.actor, actor());
    assert_eq!(
        audit.reason.as_ref().map(iam_domain::AuditReason::as_str),
        Some("last_administrator")
    );
    assert_eq!(audit.target.target_id(), FIRST);
    assert_eq!(doubles.lock.taken(), [ADMINISTRATORS_LOCK]);
    assert_eq!(doubles.lock.held(), Vec::<String>::new());
}

#[tokio::test]
async fn one_of_two_administrators_can_be_revoked_while_the_lock_is_held() {
    let (safeguard, doubles) = administrators(vec![assignment(FIRST), assignment(SECOND)]);

    let admission = safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap();

    assert_eq!(doubles.lock.held(), [ADMINISTRATORS_LOCK]);
    drop(admission);
    assert_eq!(doubles.lock.held(), Vec::<String>::new());
    assert_eq!(doubles.audit.recorded().len(), 0);
}

#[tokio::test]
async fn an_expired_or_project_scoped_or_revoked_administrator_does_not_count() {
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at())),
        ..assignment(SECOND)
    };
    let revoked = UserRoleParts {
        revoked_at: Some(at()),
        ..assignment(THIRD)
    };
    let (safeguard, _doubles) = administrators(vec![assignment(FIRST), expired, revoked]);

    let error = safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
}

#[tokio::test]
async fn an_earlier_expiry_of_the_last_administrator_is_refused_and_audited_as_an_update() {
    let (safeguard, doubles) = administrators(vec![assignment(FIRST)]);

    let error = safeguard
        .admit_expiry(&assignment(FIRST), Some(later(1)), &actor())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
    let recorded = doubles.audit.recorded();
    assert_eq!(
        recorded[0].event().parts().action.as_str(),
        "user_role.update"
    );
}

#[tokio::test]
async fn clearing_or_extending_the_expiry_of_the_last_administrator_is_admitted() {
    let expiring = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(later(5))),
        ..assignment(FIRST)
    };
    let (safeguard, doubles) = administrators(vec![expiring.clone()]);

    safeguard
        .admit_expiry(&expiring, None, &actor())
        .await
        .unwrap();
    safeguard
        .admit_expiry(&expiring, Some(later(9)), &actor())
        .await
        .unwrap();

    assert_eq!(doubles.audit.recorded().len(), 0);
}

#[tokio::test]
async fn an_assignment_of_another_role_is_admitted_without_the_lock() {
    let (safeguard, doubles) = safeguard(
        FakeRoleRepository::holding(vec![role("Billing", RoleKind::Custom)]),
        FakeUserRoleRepository::holding(vec![assignment(FIRST)]),
    );

    safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap();

    assert_eq!(doubles.lock.taken(), Vec::<String>::new());
}

#[tokio::test]
async fn an_assignment_of_a_role_that_no_longer_exists_is_admitted() {
    let (safeguard, doubles) = safeguard(
        FakeRoleRepository::new(),
        FakeUserRoleRepository::holding(vec![assignment(FIRST)]),
    );

    safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap();

    assert_eq!(doubles.lock.taken(), Vec::<String>::new());
}

fn numbered(number: u32) -> String {
    format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")
}

#[tokio::test]
async fn another_administrator_beyond_the_first_page_is_found() {
    let project = ProjectId::parse(THIRD).unwrap();
    let mut everyone: Vec<UserRoleParts> = (1..=100)
        .map(|number| UserRoleParts {
            scope: AssignmentScope::Project(project),
            ..assignment(&numbered(number))
        })
        .collect();
    everyone.push(assignment(&numbered(101)));
    everyone.push(assignment(FIRST));
    let (safeguard, _doubles) = administrators(everyone);

    let admission = safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await;

    assert!(admission.is_ok(), "{admission:?}");
}

#[tokio::test]
async fn a_full_page_of_assignments_that_are_no_administrators_ends_in_a_refusal() {
    let project = ProjectId::parse(THIRD).unwrap();
    let mut everyone: Vec<UserRoleParts> = (1..=100)
        .map(|number| UserRoleParts {
            scope: AssignmentScope::Project(project),
            ..assignment(&numbered(number))
        })
        .collect();
    everyone.push(assignment(FIRST));
    let (safeguard, _doubles) = administrators(everyone);

    let error = safeguard
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
}

#[tokio::test]
async fn unreadable_storage_is_a_storage_failure() {
    let roles = safeguard(
        FakeRoleRepository::failing(),
        FakeUserRoleRepository::holding(vec![assignment(FIRST)]),
    )
    .0;
    let assignments = safeguard(
        FakeRoleRepository::holding(vec![administrator_role()]),
        FakeUserRoleRepository::failing(),
    )
    .0;

    let role_error = roles
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();
    let assignment_error = assignments
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();

    assert!(matches!(role_error, IamError::Storage(_)), "{role_error:?}");
    assert!(
        matches!(assignment_error, IamError::Storage(_)),
        "{assignment_error:?}"
    );
}

#[tokio::test]
async fn an_unavailable_lock_or_audit_log_is_a_storage_failure() {
    let build = |lock: FakeStartupLock, audit: FakeSecurityAuditLog| {
        AdministratorSafeguard::new(
            SafeguardPorts {
                roles: Arc::new(FakeRoleRepository::holding(vec![administrator_role()])),
                user_roles: Arc::new(FakeUserRoleRepository::holding(vec![assignment(FIRST)])),
                audit_log: Arc::new(audit),
                startup_lock: Arc::new(lock),
            },
            Arc::new(FixedClock::at(at())),
            Arc::new(SequenceUuidGenerator::starting_at(1)),
        )
    };

    let lock = build(FakeStartupLock::failing(), FakeSecurityAuditLog::new())
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();
    let audit = build(FakeStartupLock::new(), FakeSecurityAuditLog::failing())
        .admit_revocation(&assignment(FIRST), &actor())
        .await
        .unwrap_err();

    assert!(matches!(lock, IamError::Storage(_)), "{lock:?}");
    assert!(matches!(audit, IamError::Storage(_)), "{audit:?}");
}
