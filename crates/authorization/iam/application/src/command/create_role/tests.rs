use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    IamUnitOfWork, IdempotencyKey, IdempotencyRequest, RequestDigest, RoleDescription, RoleId,
    RoleKind,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{CreateRoleCommand, CreateRoleCommandHandler};
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

fn command(name: &str) -> CreateRoleCommand {
    CreateRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        role_id: RoleId::parse(ROLE).unwrap(),
        actor: actor(),
        name: name.to_owned(),
        description: Some("Manages invoices.".to_owned()),
        idempotency: None,
    }
}

fn handler(unit_of_work: &Arc<FakeIamUnitOfWork>) -> CreateRoleCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    CreateRoleCommandHandler::new(
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(CreateRoleCommand::NAME, "CreateRoleCommand");
}

#[tokio::test]
async fn a_valid_role_is_committed_as_one_insert_with_its_event_and_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("Billing"))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command("x").change_id);
    assert_eq!(parts.effect, DecisionEffect::Unaffected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    let [ChangeStatement::SaveRole(statement)] = parts.statements.as_slice() else {
        panic!("one role insert expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), None);
    assert_eq!(statement.role().id, command("x").role_id);
    assert_eq!(statement.role().name.as_str(), "Billing");
    assert_eq!(
        statement
            .role()
            .description
            .as_ref()
            .map(RoleDescription::as_str),
        Some("Manages invoices.")
    );
    assert_eq!(statement.role().kind, RoleKind::Custom);
    assert_eq!(statement.role().version, EntityVersion::INITIAL);
    assert_eq!(statement.role().created_at, at());
    assert_eq!(statement.actor(), &actor());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.role.created"]);
    assert_eq!(parts.events[0].parts().actor, actor());
    assert_eq!(parts.events[0].parts().occurred_at, at());
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_role_and_the_time_of_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("Billing"))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "role.create");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "role");
    assert_eq!(audit.target.target_id(), command("x").role_id.to_string());
    assert_eq!(audit.occurred_at, at());
    assert_eq!(audit.before, None);
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("kind=custom version=1")
    );
    assert_eq!(audit.idempotency_key, None);
    assert_eq!(audit.reason, None);
    assert_eq!(audit.policy_version, None);
    assert_eq!(committed[0].parts().idempotency, None);
}

#[tokio::test]
async fn the_event_and_the_audit_record_take_distinct_identifiers_from_the_generator() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("Billing"))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let event_id = committed[0].parts().events[0].parts().id;
    let audit_id = committed[0].parts().audit.parts().id.as_uuid();
    assert_ne!(event_id, audit_id);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("create-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let command = CreateRoleCommand {
        idempotency: Some(request.clone()),
        ..command("Billing")
    };

    handler(&unit_of_work).handle(command).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn an_invalid_name_and_description_are_refused_with_every_violation_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let invalid = CreateRoleCommand {
        description: Some("d".repeat(1_001)),
        ..command("")
    };

    let error = handler(&unit_of_work).handle(invalid).await.unwrap_err();

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
async fn a_name_with_a_control_character_is_refused() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(&unit_of_work)
        .handle(command("Bill\ning"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Invalid(_)), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_change_that_the_unit_of_work_already_stored_is_a_conflict() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(&unit_of_work);
    handler.handle(command("Billing")).await.unwrap();

    let error = handler.handle(command("Billing")).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(&unit_of_work)
        .handle(command("Billing"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
