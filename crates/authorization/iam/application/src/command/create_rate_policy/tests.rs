use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    GatewayStatement, IamUnitOfWork, IdempotencyKey, IdempotencyRequest, RateFallback, RateKeyKind,
    RatePolicyId, RequestDigest,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{CreateRatePolicyCommand, CreateRatePolicyCommandHandler};
use crate::error::IamError;
use crate::rate_policy_values::RatePolicyValues;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn values(name: &str) -> RatePolicyValues {
    RatePolicyValues {
        name: name.to_owned(),
        key_kind: RateKeyKind::SubjectRoute,
        limit: 100,
        period_ms: 60_000,
        burst: 20,
        fallback: RateFallback::Divided,
    }
}

fn command(name: &str) -> CreateRatePolicyCommand {
    CreateRatePolicyCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        rate_policy_id: RatePolicyId::parse(POLICY).unwrap(),
        actor: actor(),
        values: values(name),
        idempotency: None,
    }
}

fn handler(unit_of_work: &Arc<FakeIamUnitOfWork>) -> CreateRatePolicyCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    CreateRatePolicyCommandHandler::new(
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(CreateRatePolicyCommand::NAME, "CreateRatePolicyCommand");
}

#[tokio::test]
async fn a_valid_policy_is_committed_as_one_insert_with_its_event_and_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("per-subject"))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command("x").change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    let [ChangeStatement::SaveGateway(statement)] = parts.statements.as_slice() else {
        panic!("one gateway write expected: {:?}", parts.statements);
    };
    let GatewayStatement::RatePolicy(statement) = statement.as_ref() else {
        panic!("a rate policy write expected: {statement:?}");
    };
    assert_eq!(statement.expected(), None);
    let policy = statement.rate_policy();
    assert_eq!(policy.id, command("x").rate_policy_id);
    assert_eq!(policy.fields.name(), "per-subject");
    assert_eq!(policy.fields.key_kind(), RateKeyKind::SubjectRoute);
    assert_eq!(policy.fields.limit(), 100);
    assert_eq!(policy.fields.period_seconds(), 60);
    assert_eq!(policy.fields.burst(), 20);
    assert_eq!(policy.fields.fallback(), RateFallback::Divided);
    assert_eq!(policy.version, EntityVersion::INITIAL);
    assert_eq!(policy.created_at, at());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.rate_policy.created"]);
    assert_eq!(parts.events[0].parts().actor, actor());
    assert_eq!(parts.events[0].parts().occurred_at, at());
    assert_eq!(unit_of_work.policy_version(), 1);
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_policy_and_the_state_after_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("per-subject"))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "rate_policy.create");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "rate_policy");
    assert_eq!(audit.target.target_id(), POLICY);
    assert_eq!(audit.occurred_at, at());
    assert_eq!(audit.before, None);
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("key=subject_route limit=100 periodMs=60000 burst=20 fallback=divided version=1")
    );
    let event_id = committed[0].parts().events[0].parts().id;
    assert_ne!(event_id, audit.id.as_uuid());
}

#[tokio::test]
async fn the_idempotency_key_is_kept_by_the_audit_record_and_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("key-1").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };

    handler(&unit_of_work)
        .handle(CreateRatePolicyCommand {
            idempotency: Some(request.clone()),
            ..command("per-subject")
        })
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key.clone())
    );
    assert_eq!(committed[0].parts().idempotency, Some(request));
}

#[tokio::test]
async fn invalid_values_are_refused_with_every_violation_and_nothing_is_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let invalid = CreateRatePolicyCommand {
        values: RatePolicyValues {
            limit: 0,
            period_ms: 1_001,
            ..values("")
        },
        ..command("")
    };

    let error = handler(&unit_of_work).handle(invalid).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["name", "limit", "periodMs"]);
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_duplicate_change_is_a_conflict() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    handler(&unit_of_work)
        .handle(command("per-subject"))
        .await
        .unwrap();

    let error = handler(&unit_of_work)
        .handle(command("per-subject"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Conflict));
}

#[tokio::test]
async fn a_failing_storage_is_a_storage_error() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(&unit_of_work)
        .handle(command("per-subject"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
