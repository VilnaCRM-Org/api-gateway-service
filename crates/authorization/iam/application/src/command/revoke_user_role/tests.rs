use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, AuditSummary, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, IamUnitOfWork, IdempotencyKey,
    IdempotencyRequest, PermissionGrantSet, RequestDigest, RoleId, RoleKind, RoleName, RoleParts,
    RoleRepository, SubjectRef, UserRoleId, UserRoleParts, UserRoleRepository,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::startup_lock::FakeStartupLock;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;

use super::{RevokeUserRoleCommand, RevokeUserRoleCommandHandler, RevokeUserRoleReads};
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

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

/// The stored assignment at version 2 that expires in the future.
fn stored() -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject: SubjectRef::user(Uuid::parse(SUBJECT).unwrap()),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: Some(AssignmentExpiry::restore(
            at().checked_add(Duration::from_hours(1)).unwrap(),
        )),
        version: version(2),
        created_by: actor(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn role() -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(std::iter::empty()).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

fn command() -> RevokeUserRoleCommand {
    RevokeUserRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
        actor: actor(),
        expected: version(2),
        idempotency: None,
    }
}

fn handler(
    user_roles: FakeUserRoleRepository,
    roles: FakeRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> RevokeUserRoleCommandHandler {
    guarded(user_roles, roles, unit_of_work).0
}

/// The handler with the audit log that its safeguard writes refusals to; the safeguard reads the
/// same assignments and roles as the handler.
fn guarded(
    user_roles: FakeUserRoleRepository,
    roles: FakeRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> (RevokeUserRoleCommandHandler, Arc<FakeSecurityAuditLog>) {
    let user_roles = Arc::new(user_roles);
    let roles = Arc::new(roles);
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let safeguard = AdministratorSafeguard::new(
        SafeguardPorts {
            roles: Arc::<FakeRoleRepository>::clone(&roles),
            user_roles: Arc::<FakeUserRoleRepository>::clone(&user_roles),
            audit_log: Arc::<FakeSecurityAuditLog>::clone(&audit),
            startup_lock: Arc::new(FakeStartupLock::new()),
        },
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(100)),
    );
    let user_roles: Arc<dyn UserRoleRepository> = user_roles;
    let roles: Arc<dyn RoleRepository> = roles;
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    let handler = RevokeUserRoleCommandHandler::new(
        RevokeUserRoleReads { user_roles, roles },
        unit_of_work,
        Arc::new(safeguard),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    (handler, audit)
}

fn administrator_role() -> RoleParts {
    RoleParts {
        name: RoleName::new("iam-platform-admin".to_owned()).unwrap(),
        kind: RoleKind::System,
        ..role()
    }
}

fn standard(unit_of_work: &Arc<FakeIamUnitOfWork>) -> RevokeUserRoleCommandHandler {
    handler(
        FakeUserRoleRepository::holding(vec![stored()]),
        FakeRoleRepository::holding(vec![role()]),
        unit_of_work,
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(RevokeUserRoleCommand::NAME, "RevokeUserRoleCommand");
}

#[tokio::test]
async fn a_revocation_is_committed_as_one_guarded_update_that_affects_decisions() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(&unit_of_work).handle(command()).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command().change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, version(3));
    assert_eq!(unit_of_work.policy_version(), 1);
    let [ChangeStatement::SaveUserRole(statement)] = parts.statements.as_slice() else {
        panic!("one assignment update expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(version(2)));
    assert_eq!(statement.user_role().version, version(3));
    assert_eq!(statement.user_role().revoked_at, Some(at()));
    assert_eq!(statement.user_role().updated_at, at());
}

#[tokio::test]
async fn the_revocation_records_the_revoked_event_with_the_role_name_and_the_cause() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(&unit_of_work).handle(command()).await.unwrap();

    let committed = unit_of_work.committed();
    let events = &committed[0].parts().events;
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.user_role.revoked"]);
    assert_eq!(events[0].parts().actor, actor());
    assert_eq!(events[0].parts().occurred_at, at());
    assert_eq!(
        events[0].parts().aggregate_id,
        command().user_role_id.as_uuid()
    );
    let data = format!("{:?}", events[0].parts().data);
    assert!(data.contains("Billing"), "{data}");
    assert!(data.contains("revoked"), "{data}");
    assert!(data.contains("userId"), "{data}");
}

#[tokio::test]
async fn the_audit_record_keeps_the_assignment_before_and_its_end_version() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(&unit_of_work).handle(command()).await.unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "user_role.revoke");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "user_role");
    assert_eq!(audit.target.target_id(), USER_ROLE);
    assert_eq!(audit.scope, Some(AssignmentScope::Global));
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some(format!("subject=user:{SUBJECT} role={ROLE} scope=global version=2").as_str())
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("revoked version=3")
    );
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let revoke = RevokeUserRoleCommand {
        expected: version(1),
        ..command()
    };

    let error = standard(&unit_of_work).handle(revoke).await.unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unknown_or_already_revoked_assignment_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let revoked = UserRoleParts {
        revoked_at: Some(at()),
        ..stored()
    };

    for user_roles in [
        FakeUserRoleRepository::new(),
        FakeUserRoleRepository::holding(vec![revoked]),
    ] {
        let roles = FakeRoleRepository::holding(vec![role()]);
        let error = handler(user_roles, roles, &unit_of_work)
            .handle(command())
            .await
            .unwrap_err();

        assert!(matches!(error, IamError::NotFound), "{error:?}");
    }
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_assignment_of_a_role_that_no_longer_exists_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(
        FakeUserRoleRepository::holding(vec![stored()]),
        FakeRoleRepository::new(),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();

    assert!(matches!(error, IamError::NotFound), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn unreadable_storage_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let assignment = handler(
        FakeUserRoleRepository::failing(),
        FakeRoleRepository::holding(vec![role()]),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();
    let role = handler(
        FakeUserRoleRepository::holding(vec![stored()]),
        FakeRoleRepository::failing(),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();

    assert!(matches!(assignment, IamError::Storage(_)), "{assignment:?}");
    assert!(matches!(role, IamError::Storage(_)), "{role:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("revoke-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let revoke = RevokeUserRoleCommand {
        idempotency: Some(request.clone()),
        ..command()
    };

    standard(&unit_of_work).handle(revoke).await.unwrap();

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

    let error = standard(&unit_of_work).handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn the_last_administrator_is_refused_audited_and_not_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let (handler, audit) = guarded(
        FakeUserRoleRepository::holding(vec![stored()]),
        FakeRoleRepository::holding(vec![administrator_role()]),
        &unit_of_work,
    );

    let error = handler.handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::LastAdministrator), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
    let recorded = audit.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].event().parts().outcome, AuditOutcome::Rejected);
    assert_eq!(
        recorded[0].event().parts().action.as_str(),
        "user_role.revoke"
    );
}

#[tokio::test]
async fn an_administrator_is_revoked_while_another_one_is_active() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let other = UserRoleParts {
        id: UserRoleId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890b0").unwrap(),
        ..stored()
    };
    let (handler, audit) = guarded(
        FakeUserRoleRepository::holding(vec![stored(), other]),
        FakeRoleRepository::holding(vec![administrator_role()]),
        &unit_of_work,
    );

    handler.handle(command()).await.unwrap();

    assert_eq!(unit_of_work.committed().len(), 1);
    assert_eq!(audit.recorded().len(), 0);
}

#[tokio::test]
async fn a_revocation_asks_for_the_escalation_check_of_the_stored_subject_and_role() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(&unit_of_work).handle(command()).await.unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Assignment {
            subject: stored().subject,
            role_id: stored().role_id,
        })
    );
}
