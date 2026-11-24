use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, AuditSummary, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, IamUnitOfWork, IdempotencyKey,
    IdempotencyRequest, PermissionGrantSet, RequestDigest, RoleId, RoleKind, RoleName, RoleParts,
    SubjectRef, UserRoleId, UserRoleParts, UserRoleRepository,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::startup_lock::FakeStartupLock;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;

use super::{UpdateUserRoleCommand, UpdateUserRoleCommandHandler};
use crate::administrator_safeguard::{AdministratorSafeguard, SafeguardPorts};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const USER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn later() -> SystemTime {
    at().checked_add(Duration::from_hours(1)).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

/// The stored assignment at version 2, with the expiry `expires_at`.
fn stored(expires_at: Option<SystemTime>) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject: SubjectRef::user(Uuid::parse(SUBJECT).unwrap()),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: expires_at.map(AssignmentExpiry::restore),
        version: version(2),
        created_by: actor(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn command(expires_at: Option<SystemTime>) -> UpdateUserRoleCommand {
    UpdateUserRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
        actor: actor(),
        expected: version(2),
        expires_at,
        idempotency: None,
    }
}

fn handler(
    user_roles: FakeUserRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> UpdateUserRoleCommandHandler {
    guarded(user_roles, FakeRoleRepository::new(), unit_of_work).0
}

/// The handler whose safeguard reads `roles` and the same assignments, with the audit log it
/// writes refusals to.
fn guarded(
    user_roles: FakeUserRoleRepository,
    roles: FakeRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> (UpdateUserRoleCommandHandler, Arc<FakeSecurityAuditLog>) {
    let user_roles = Arc::new(user_roles);
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let safeguard = AdministratorSafeguard::new(
        SafeguardPorts {
            roles: Arc::new(roles),
            user_roles: Arc::<FakeUserRoleRepository>::clone(&user_roles),
            audit_log: Arc::<FakeSecurityAuditLog>::clone(&audit),
            startup_lock: Arc::new(FakeStartupLock::new()),
        },
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(100)),
    );
    let user_roles: Arc<dyn UserRoleRepository> = user_roles;
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    let handler = UpdateUserRoleCommandHandler::new(
        user_roles,
        unit_of_work,
        Arc::new(safeguard),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    (handler, audit)
}

fn administrator_role() -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("iam-platform-admin".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::System,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn holding(expires_at: Option<SystemTime>) -> FakeUserRoleRepository {
    FakeUserRoleRepository::holding(vec![stored(expires_at)])
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(UpdateUserRoleCommand::NAME, "UpdateUserRoleCommand");
}

#[tokio::test]
async fn an_expiry_is_committed_as_one_guarded_update_that_affects_decisions() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(holding(None), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command(None).change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, version(3));
    assert_eq!(unit_of_work.policy_version(), 1);
    let [ChangeStatement::SaveUserRole(statement)] = parts.statements.as_slice() else {
        panic!("one assignment update expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(version(2)));
    assert_eq!(statement.user_role().version, version(3));
    assert_eq!(statement.user_role().updated_at, at());
    assert_eq!(
        statement.user_role().expires_at.map(AssignmentExpiry::at),
        Some(later())
    );
    assert_eq!(statement.user_role().revoked_at, None);
}

#[tokio::test]
async fn the_update_records_the_updated_event_of_the_actor() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(holding(None), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let events = &committed[0].parts().events;
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.user_role.updated"]);
    assert_eq!(events[0].parts().actor, actor());
    assert_eq!(events[0].parts().occurred_at, at());
    assert_eq!(
        events[0].parts().aggregate_id,
        command(None).user_role_id.as_uuid()
    );
}

#[tokio::test]
async fn clearing_the_expiry_stores_none() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(holding(Some(later())), &unit_of_work)
        .handle(command(None))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveUserRole(statement)] = committed[0].parts().statements.as_slice()
    else {
        panic!("one assignment update expected");
    };
    assert_eq!(statement.user_role().expires_at, None);
    assert_eq!(statement.user_role().version, version(3));
}

#[tokio::test]
async fn the_audit_record_keeps_the_expiry_and_version_before_and_after() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(holding(None), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "user_role.update");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "user_role");
    assert_eq!(audit.target.target_id(), USER_ROLE);
    assert_eq!(audit.scope, Some(AssignmentScope::Global));
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("expiresAt=none version=2")
    );
    let after = audit.after.as_ref().map(AuditSummary::as_str).unwrap();
    assert!(after.starts_with("expiresAt=20"), "{after}");
    assert!(after.ends_with("version=3"), "{after}");
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let update = UpdateUserRoleCommand {
        expected: version(1),
        ..command(Some(later()))
    };

    let error = handler(holding(None), &unit_of_work)
        .handle(update)
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_expiry_that_is_not_in_the_future_is_a_violation_of_expires_at() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(holding(None), &unit_of_work)
        .handle(command(Some(at())))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "expiresAt");
    assert_eq!(violations[0].code, "future");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unknown_or_revoked_assignment_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let revoked = UserRoleParts {
        revoked_at: Some(at()),
        ..stored(None)
    };

    for user_roles in [
        FakeUserRoleRepository::new(),
        FakeUserRoleRepository::holding(vec![revoked]),
    ] {
        let error = handler(user_roles, &unit_of_work)
            .handle(command(Some(later())))
            .await
            .unwrap_err();

        assert!(matches!(error, IamError::NotFound), "{error:?}");
    }
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unreadable_assignment_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(FakeUserRoleRepository::failing(), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("extend-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let update = UpdateUserRoleCommand {
        idempotency: Some(request.clone()),
        ..command(Some(later()))
    };

    handler(holding(None), &unit_of_work)
        .handle(update)
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(holding(None), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn an_expiry_of_the_last_administrator_is_refused_audited_and_not_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let (handler, audit) = guarded(
        holding(None),
        FakeRoleRepository::holding(vec![administrator_role()]),
        &unit_of_work,
    );

    let error = handler.handle(command(Some(later()))).await.unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
    let recorded = audit.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].event().parts().outcome, AuditOutcome::Rejected);
    assert_eq!(
        recorded[0].event().parts().action.as_str(),
        "user_role.update"
    );
}

#[tokio::test]
async fn clearing_the_expiry_of_the_last_administrator_is_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let (handler, audit) = guarded(
        holding(Some(later())),
        FakeRoleRepository::holding(vec![administrator_role()]),
        &unit_of_work,
    );

    handler.handle(command(None)).await.unwrap();

    assert_eq!(unit_of_work.committed().len(), 1);
    assert_eq!(audit.recorded().len(), 0);
}

#[tokio::test]
async fn a_stale_version_wins_over_the_last_administrator_refusal() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let (handler, audit) = guarded(
        holding(None),
        FakeRoleRepository::holding(vec![administrator_role()]),
        &unit_of_work,
    );
    let stale = UpdateUserRoleCommand {
        expected: version(1),
        ..command(Some(later()))
    };

    let error = handler.handle(stale).await.unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed), "{error:?}");
    assert_eq!(audit.recorded().len(), 0);
}

#[tokio::test]
async fn an_expiry_change_asks_for_the_escalation_check_of_the_stored_subject_and_role() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(holding(None), &unit_of_work)
        .handle(command(Some(later())))
        .await
        .unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Assignment {
            subject: stored(None).subject,
            role_id: stored(None).role_id,
        })
    );
}
