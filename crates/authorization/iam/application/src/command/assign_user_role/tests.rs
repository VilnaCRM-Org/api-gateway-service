use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, AuditSummary, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, IamUnitOfWork, IdempotencyKey,
    IdempotencyRequest, PermissionGrant, PermissionGrantSet, ProjectId, RequestDigest, RoleId,
    RoleKind, RoleName, RoleParts, RoleRepository, ServiceName, SubjectRef, UserRoleId,
};
use rstest::rstest;
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{AssignUserRoleCommand, AssignUserRoleCommandHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const USER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890b0";

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

fn command() -> AssignUserRoleCommand {
    AssignUserRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
        actor: actor(),
        subject: SubjectRef::user(Uuid::parse(SUBJECT).unwrap()),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: None,
        idempotency: None,
    }
}

/// The role that every assignment names, holding `grants`.
fn role(grants: &[&str]) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(
            grants
                .iter()
                .map(|grant| PermissionGrant::parse(grant).unwrap()),
        )
        .unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

fn handler(
    roles: FakeRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> AssignUserRoleCommandHandler {
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    AssignUserRoleCommandHandler::new(
        roles,
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn plain_handler(unit_of_work: &Arc<FakeIamUnitOfWork>) -> AssignUserRoleCommandHandler {
    handler(FakeRoleRepository::holding(vec![role(&[])]), unit_of_work)
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(AssignUserRoleCommand::NAME, "AssignUserRoleCommand");
}

#[tokio::test]
async fn an_assignment_is_committed_as_one_insert_that_affects_decisions() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    plain_handler(&unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command().change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    assert_eq!(unit_of_work.policy_version(), 1);
    let [ChangeStatement::SaveUserRole(statement)] = parts.statements.as_slice() else {
        panic!("one assignment insert expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), None);
    assert_eq!(statement.user_role().id, command().user_role_id);
    assert_eq!(statement.user_role().subject, command().subject);
    assert_eq!(statement.user_role().role_id, command().role_id);
    assert_eq!(statement.user_role().scope, AssignmentScope::Global);
    assert_eq!(statement.user_role().expires_at, None);
    assert_eq!(statement.user_role().version, EntityVersion::INITIAL);
    assert_eq!(statement.user_role().created_by, actor());
    assert_eq!(statement.user_role().created_at, at());
}

#[tokio::test]
async fn a_plain_role_records_only_the_assigned_event_with_the_subject_and_the_user_id() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    plain_handler(&unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let events = &committed[0].parts().events;
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.user_role.assigned"]);
    assert_eq!(events[0].parts().actor, actor());
    assert_eq!(events[0].parts().occurred_at, at());
    assert_eq!(
        events[0].parts().aggregate_id,
        command().user_role_id.as_uuid()
    );
    let data = format!("{:?}", events[0].parts().data);
    assert!(data.contains("userId"), "{data}");
    assert!(data.contains("subject"), "{data}");
    assert!(data.contains("Billing"), "{data}");
}

#[rstest]
#[case::wildcard(&["rest:billing:*"], &["rest:billing:*"])]
#[case::reserved_key(&["iam:audit:read"], &["iam:audit:read"])]
#[case::mixed(
    &["rest:billing:GET /invoices", "iam:audit:read", "rest:billing:*"],
    &["iam:audit:read", "rest:billing:*"]
)]
#[tokio::test]
async fn a_role_with_privileged_grants_also_records_the_security_alert_with_those_keys(
    #[case] grants: &[&str],
    #[case] privileged: &[&str],
) {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = FakeRoleRepository::holding(vec![role(grants)]);

    handler(roles, &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let events = &committed[0].parts().events;
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(
        types,
        ["iam.user_role.assigned", "iam.privileged_role.assigned"]
    );
    let alert = format!("{:?}", events[1].parts().data);
    for key in privileged {
        assert!(alert.contains(key), "{alert}");
    }
    assert!(!alert.contains("GET /invoices"), "{alert}");
    assert_ne!(events[0].parts().id, events[1].parts().id);
}

#[tokio::test]
async fn a_role_without_privileged_grants_records_no_alert_even_with_ordinary_keys() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = FakeRoleRepository::holding(vec![role(&["rest:billing:GET /invoices"])]);

    handler(roles, &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed()[0].parts().events.len(), 1);
}

#[rstest]
#[case::global(AssignmentScope::Global, "global")]
#[case::project(AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap()), "project:0190f2a8-7b3c-7d4e-8f10-1234567890b0")]
#[tokio::test]
async fn the_audit_record_names_the_actor_the_assignment_the_scope_and_the_time(
    #[case] scope: AssignmentScope,
    #[case] text: &str,
) {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let assign = AssignUserRoleCommand { scope, ..command() };

    plain_handler(&unit_of_work).handle(assign).await.unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "user_role.assign");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "user_role");
    assert_eq!(audit.target.target_id(), USER_ROLE);
    assert_eq!(audit.scope, Some(scope));
    assert_eq!(audit.occurred_at, at());
    assert_eq!(audit.before, None);
    let after = audit.after.as_ref().map(AuditSummary::as_str).unwrap();
    assert_eq!(
        after,
        format!("subject=user:{SUBJECT} role={ROLE} scope={text} version=1")
    );
    assert_eq!(audit.policy_version, None);
}

#[tokio::test]
async fn a_service_subject_is_assigned_like_a_user_but_has_no_user_id() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let assign = AssignUserRoleCommand {
        subject: SubjectRef::service(ServiceName::new("billing-worker").unwrap()),
        ..command()
    };

    plain_handler(&unit_of_work).handle(assign).await.unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveUserRole(statement)] = committed[0].parts().statements.as_slice()
    else {
        panic!("one assignment insert expected");
    };
    assert_eq!(
        statement.user_role().subject.to_string(),
        "service:billing-worker"
    );
    let data = format!("{:?}", committed[0].parts().events[0].parts().data);
    assert!(!data.contains("userId"), "{data}");
}

#[tokio::test]
async fn an_expiry_in_the_future_is_stored() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let assign = AssignUserRoleCommand {
        expires_at: Some(later()),
        ..command()
    };

    plain_handler(&unit_of_work).handle(assign).await.unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveUserRole(statement)] = committed[0].parts().statements.as_slice()
    else {
        panic!("one assignment insert expected");
    };
    assert_eq!(
        statement.user_role().expires_at.map(AssignmentExpiry::at),
        Some(later())
    );
}

#[rstest]
#[case::now(at())]
#[case::past(SystemTime::UNIX_EPOCH)]
#[tokio::test]
async fn an_expiry_that_is_not_in_the_future_is_a_violation_of_expires_at_before_any_commit(
    #[case] expires_at: SystemTime,
) {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let assign = AssignUserRoleCommand {
        expires_at: Some(expires_at),
        ..command()
    };

    let error = plain_handler(&unit_of_work)
        .handle(assign)
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

#[rstest]
#[case::unknown(FakeRoleRepository::new())]
#[case::other_role(FakeRoleRepository::holding(vec![RoleParts {
    id: RoleId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ff").unwrap(),
    ..role(&[])
}]))]
#[tokio::test]
async fn an_unknown_role_is_a_violation_of_role_id_before_any_commit(
    #[case] roles: FakeRoleRepository,
) {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(roles, &unit_of_work)
        .handle(command())
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "roleId");
    assert_eq!(violations[0].code, "exists");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unreadable_role_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(FakeRoleRepository::failing(), &unit_of_work)
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("assign-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let assign = AssignUserRoleCommand {
        idempotency: Some(request.clone()),
        ..command()
    };

    plain_handler(&unit_of_work).handle(assign).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn a_change_that_the_unit_of_work_already_stored_is_a_conflict() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = plain_handler(&unit_of_work);
    handler.handle(command()).await.unwrap();

    let error = handler.handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = plain_handler(&unit_of_work)
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
