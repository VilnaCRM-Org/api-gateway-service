use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    IamUnitOfWork, IdempotencyKey, IdempotencyRequest, PermissionGrantSet, RequestDigest,
    RoleDescription, RoleId, RoleKind, RoleName, RoleParts, RoleRepository,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{DescriptionUpdate, UpdateRoleCommand, UpdateRoleCommandHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn stored(kind: RoleKind, version: i64) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: Some(RoleDescription::new("Invoices".to_owned()).unwrap()),
        kind,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::new(version).unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn command(expected: i64) -> UpdateRoleCommand {
    UpdateRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        role_id: RoleId::parse(ROLE).unwrap(),
        actor: actor(),
        expected: EntityVersion::new(expected).unwrap(),
        name: Some("Accounting".to_owned()),
        description: DescriptionUpdate::Keep,
        idempotency: None,
    }
}

fn handler(
    roles: Vec<RoleParts>,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> UpdateRoleCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::holding(roles));
    UpdateRoleCommandHandler::new(
        roles,
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(UpdateRoleCommand::NAME, "UpdateRoleCommand");
}

#[test]
fn the_description_is_kept_unless_the_update_says_otherwise() {
    assert_eq!(DescriptionUpdate::default(), DescriptionUpdate::Keep);
}

#[tokio::test]
async fn a_rename_is_committed_as_one_guarded_update_with_its_event_and_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(command(1))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.effect, DecisionEffect::Unaffected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [ChangeStatement::SaveRole(statement)] = parts.statements.as_slice() else {
        panic!("one role update expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.role().name.as_str(), "Accounting");
    assert_eq!(
        statement
            .role()
            .description
            .as_ref()
            .map(RoleDescription::as_str),
        Some("Invoices")
    );
    assert_eq!(statement.role().version, EntityVersion::new(2).unwrap());
    assert_eq!(statement.role().updated_at, at());
    assert_eq!(statement.actor(), &actor());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.role.updated"]);
    assert_eq!(parts.events[0].parts().actor, actor());
    assert_eq!(parts.events[0].parts().occurred_at, at());
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_role_and_the_versions_before_and_after() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(command(1))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "role.update");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "role");
    assert_eq!(audit.target.target_id(), ROLE);
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("kind=custom version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("kind=custom version=2")
    );
    assert_eq!(audit.policy_version, None);
    assert_eq!(committed[0].parts().idempotency, None);
}

#[tokio::test]
async fn the_event_and_the_audit_record_take_distinct_identifiers_from_the_generator() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(command(1))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let event_id = committed[0].parts().events[0].parts().id;
    let audit_id = committed[0].parts().audit.parts().id.as_uuid();
    assert_ne!(event_id, audit_id);
}

#[tokio::test]
async fn the_description_can_be_replaced_or_removed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let replaced = UpdateRoleCommand {
        name: None,
        description: DescriptionUpdate::Set("Refunds".to_owned()),
        ..command(1)
    };
    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(replaced)
        .await
        .unwrap();

    let unit_of_work_removed = Arc::new(FakeIamUnitOfWork::new());
    let removed = UpdateRoleCommand {
        name: None,
        description: DescriptionUpdate::Remove,
        ..command(1)
    };
    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work_removed)
        .handle(removed)
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveRole(statement)] = committed[0].parts().statements.as_slice() else {
        panic!("one role update expected");
    };
    assert_eq!(statement.role().name.as_str(), "Billing");
    assert_eq!(
        statement
            .role()
            .description
            .as_ref()
            .map(RoleDescription::as_str),
        Some("Refunds")
    );
    let committed = unit_of_work_removed.committed();
    let [ChangeStatement::SaveRole(statement)] = committed[0].parts().statements.as_slice() else {
        panic!("one role update expected");
    };
    assert_eq!(statement.role().description, None);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("rename-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let command = UpdateRoleCommand {
        idempotency: Some(request.clone()),
        ..command(1)
    };

    handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(command)
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
async fn an_unknown_role_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(Vec::new(), &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_system_role_is_forbidden_and_nothing_is_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(vec![stored(RoleKind::System, 1)], &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(vec![stored(RoleKind::Custom, 3)], &unit_of_work)
        .handle(command(2))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_invalid_name_and_description_are_refused_with_every_violation_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let invalid = UpdateRoleCommand {
        name: Some(String::new()),
        description: DescriptionUpdate::Set("d".repeat(1_001)),
        ..command(1)
    };

    let error = handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(invalid)
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["name", "description"]);
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_role_repository_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let unit: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let handler = UpdateRoleCommandHandler::new(
        Arc::new(FakeRoleRepository::failing()),
        unit,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn a_change_that_the_unit_of_work_already_stored_is_a_conflict() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(vec![stored(RoleKind::Custom, 1)], &unit_of_work);
    handler.handle(command(1)).await.unwrap();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 1);
}
