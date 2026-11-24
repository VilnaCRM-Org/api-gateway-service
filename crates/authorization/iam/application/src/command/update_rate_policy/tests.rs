use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    GatewayStatement, IamUnitOfWork, RateFallback, RateKeyKind, RatePolicyId, RatePolicyParts,
    RatePolicyRepository,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{UpdateRatePolicyCommand, UpdateRatePolicyCommandHandler};
use crate::error::IamError;
use crate::rate_policy_fixtures::{POLICY, rate_policy};
use crate::rate_policy_values::RatePolicyPatch;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(600_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn command(expected: i64, patch: RatePolicyPatch) -> UpdateRatePolicyCommand {
    UpdateRatePolicyCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        rate_policy_id: RatePolicyId::parse(POLICY).unwrap(),
        actor: actor(),
        expected: EntityVersion::new(expected).unwrap(),
        patch,
        idempotency: None,
    }
}

fn raise_limit() -> RatePolicyPatch {
    RatePolicyPatch {
        limit: Some(200),
        key_kind: Some(RateKeyKind::Ip),
        ..RatePolicyPatch::default()
    }
}

fn handler(
    stored: Vec<RatePolicyParts>,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> UpdateRatePolicyCommandHandler {
    let policies: Arc<dyn RatePolicyRepository> =
        Arc::new(FakeRatePolicyRepository::holding(stored));
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    UpdateRatePolicyCommandHandler::new(
        policies,
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(UpdateRatePolicyCommand::NAME, "UpdateRatePolicyCommand");
}

#[tokio::test]
async fn a_patch_is_committed_as_one_guarded_update_that_keeps_the_other_members() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![rate_policy(1)], &unit_of_work)
        .handle(command(1, raise_limit()))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [ChangeStatement::SaveGateway(statement)] = parts.statements.as_slice() else {
        panic!("one gateway write expected: {:?}", parts.statements);
    };
    let GatewayStatement::RatePolicy(statement) = statement.as_ref() else {
        panic!("a rate policy write expected: {statement:?}");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    let fields = &statement.rate_policy().fields;
    assert_eq!(fields.name(), "per-subject");
    assert_eq!(fields.key_kind(), RateKeyKind::Ip);
    assert_eq!(fields.limit(), 200);
    assert_eq!(fields.period_seconds(), 60);
    assert_eq!(fields.burst(), 20);
    assert_eq!(fields.fallback(), RateFallback::Divided);
    assert_eq!(statement.rate_policy().updated_at, at());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.rate_policy.updated"]);
}

#[tokio::test]
async fn the_audit_record_keeps_the_states_before_and_after() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![rate_policy(1)], &unit_of_work)
        .handle(command(1, raise_limit()))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "rate_policy.update");
    assert_eq!(audit.target.target_id(), POLICY);
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("key=subject_route limit=100 periodMs=60000 burst=20 fallback=divided version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("key=ip limit=200 periodMs=60000 burst=20 fallback=divided version=2")
    );
}

#[tokio::test]
async fn an_unknown_policy_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(Vec::new(), &unit_of_work)
        .handle(command(1, raise_limit()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(vec![rate_policy(2)], &unit_of_work)
        .handle(command(1, raise_limit()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn invalid_values_are_refused_with_their_violations() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let patch = RatePolicyPatch {
        period_ms: Some(999),
        burst: Some(-5),
        ..RatePolicyPatch::default()
    };

    let error = handler(vec![rate_policy(1)], &unit_of_work)
        .handle(command(1, patch))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["periodMs", "burst"]);
}

#[tokio::test]
async fn a_failing_storage_is_a_storage_error() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(vec![rate_policy(1)], &unit_of_work)
        .handle(command(1, raise_limit()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
