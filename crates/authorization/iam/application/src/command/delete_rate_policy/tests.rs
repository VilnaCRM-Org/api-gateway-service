use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    GatewayPrecondition, GatewayStatement, HttpMethod, IamUnitOfWork, RatePolicyId,
    RatePolicyParts, RatePolicyRepository, RouteParts, RouteRepository, UpstreamId,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::route::{FakeRouteRepository, route, route_draft};
use test_support::seed::TestRng;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{DeleteRatePolicyCommand, DeleteRatePolicyCommandHandler};
use crate::error::IamError;
use crate::rate_policy_fixtures::{POLICY, rate_policy};

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

fn command(expected: i64) -> DeleteRatePolicyCommand {
    DeleteRatePolicyCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        rate_policy_id: RatePolicyId::parse(POLICY).unwrap(),
        actor: actor(),
        expected: EntityVersion::new(expected).unwrap(),
        idempotency: None,
    }
}

/// A route that applies the stored rate policy.
fn referencing_route() -> RouteParts {
    let mut rng = TestRng::from_env();
    let mut draft = route_draft(
        "api.example.com",
        "/users",
        &[HttpMethod::Get],
        "core",
        UpstreamId::from_uuid(Uuid::parse(USER).unwrap()),
    );
    draft.rate_policies = vec![RatePolicyId::parse(POLICY).unwrap()];
    route(&mut rng, &draft).parts().clone()
}

fn handler(
    stored: Vec<RatePolicyParts>,
    routes: Vec<RouteParts>,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> DeleteRatePolicyCommandHandler {
    let policies: Arc<dyn RatePolicyRepository> =
        Arc::new(FakeRatePolicyRepository::holding(stored));
    let routes: Arc<dyn RouteRepository> = Arc::new(FakeRouteRepository::holding(routes));
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    DeleteRatePolicyCommandHandler::new(
        policies,
        routes,
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(DeleteRatePolicyCommand::NAME, "DeleteRatePolicyCommand");
}

#[tokio::test]
async fn an_unreferenced_policy_is_deleted_with_a_tombstone_its_event_and_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(vec![rate_policy(1)], Vec::new(), &unit_of_work)
        .handle(command(1))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [
        ChangeStatement::ExpectGateway(precondition),
        ChangeStatement::SaveGateway(statement),
    ] = parts.statements.as_slice()
    else {
        panic!(
            "a reference check and one gateway write expected: {:?}",
            parts.statements
        );
    };
    assert_eq!(
        precondition.as_ref(),
        &GatewayPrecondition::RatePolicyUnreferenced(RatePolicyId::parse(POLICY).unwrap())
    );
    let GatewayStatement::RatePolicy(statement) = statement.as_ref() else {
        panic!("a rate policy write expected: {statement:?}");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.rate_policy().deleted_at, Some(at()));
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.rate_policy.deleted"]);
    let audit = parts.audit.parts();
    assert_eq!(audit.action.as_str(), "rate_policy.delete");
    assert_eq!(audit.target.target_id(), POLICY);
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("key=subject_route limit=100 periodMs=60000 burst=20 fallback=divided version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("deleted version=2")
    );
}

#[tokio::test]
async fn a_policy_that_a_route_references_is_a_conflict_and_nothing_is_committed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(
        vec![rate_policy(1)],
        vec![referencing_route()],
        &unit_of_work,
    )
    .handle(command(1))
    .await
    .unwrap_err();

    assert!(matches!(error, IamError::ReferencedByRoute));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unknown_policy_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(Vec::new(), Vec::new(), &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(vec![rate_policy(3)], Vec::new(), &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_route_read_is_a_storage_error() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let policies: Arc<dyn RatePolicyRepository> =
        Arc::new(FakeRatePolicyRepository::holding(vec![rate_policy(1)]));
    let routes: Arc<dyn RouteRepository> = Arc::new(FakeRouteRepository::failing());
    let unit_of_work_port: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let handler = DeleteRatePolicyCommandHandler::new(
        policies,
        routes,
        unit_of_work_port,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_storage_is_a_storage_error() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(vec![rate_policy(1)], Vec::new(), &unit_of_work)
        .handle(command(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
