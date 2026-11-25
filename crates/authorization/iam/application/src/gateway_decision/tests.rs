use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessCheck, AccessTarget, BootClock as _, BootInstant, Credential, DecisionOutcome,
    DecisionReason, FreshnessRule, GraphQlTarget, PermissionsTarget, PolicyReadRepository,
    PolicyVersion, ServiceName, TokenRejection,
};
use shared_domain::QueryHandler as _;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::decision_snapshot::DecisionSnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_view::FakePolicyView;
use test_support::token::FakeTokenRepository;

use super::{GatewayValidateAccessBatchQueryHandler, GatewayValidateAccessQueryHandler};

mod access_log;
use crate::access_decision_service::AccessDecisionService;
use crate::freshness::FreshnessState;
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};
use crate::read_your_writes::{PolicyVersionBoard, ReadYourWritesBarrier};
use crate::service_catalog_loader::ServiceCatalogLoader;
use crate::snapshot_policy_reads::SnapshotPolicyReads;

const HARD: Duration = Duration::from_secs(15);

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

struct Scenario {
    single: GatewayValidateAccessQueryHandler,
    batch: GatewayValidateAccessBatchQueryHandler,
    tokens: Arc<FakeTokenRepository>,
    clock: Arc<FakeBootClock>,
}

/// A gateway at policy version 5 with a fresh proof; the credential `expired` is refused.
fn scenario() -> Scenario {
    scenario_with(None)
}

/// The same gateway behind the read-your-writes barrier over `board`, which waits one second.
fn barred_scenario(board: &Arc<PolicyVersionBoard>) -> Scenario {
    scenario_with(Some(Arc::clone(board)))
}

fn scenario_with(board: Option<Arc<PolicyVersionBoard>>) -> Scenario {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD, Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    ));
    state.attach(
        FreshnessProof {
            taken_at: clock.now(),
            watermark: 1,
        },
        version(5),
    );
    let view = Arc::new(FakePolicyView::with_snapshot(Arc::new(
        DecisionSnapshot::at(version(5)),
    )));
    let barrier = board.map(|board| {
        Arc::new(ReadYourWritesBarrier::new(
            Arc::<FakePolicyView>::clone(&view),
            board,
            Duration::from_secs(1),
        ))
    });
    let reads = Arc::new(SnapshotPolicyReads::new(view, state));
    let policy: Arc<dyn PolicyReadRepository> = Arc::<SnapshotPolicyReads>::clone(&reads);
    let tokens = Arc::new(FakeTokenRepository::new().rejecting("expired", TokenRejection::Expired));
    let decisions = Arc::new(AccessDecisionService::new(
        Arc::<FakeTokenRepository>::clone(&tokens),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    ));
    let mut single =
        GatewayValidateAccessQueryHandler::new(Arc::clone(&decisions), Arc::clone(&reads));
    let mut batch = GatewayValidateAccessBatchQueryHandler::new(
        decisions,
        reads,
        Arc::<FakeTokenRepository>::clone(&tokens),
    );
    if let Some(barrier) = barrier {
        single = single.with_barrier(Arc::clone(&barrier));
        batch = batch.with_barrier(barrier);
    }
    Scenario {
        single,
        batch,
        tokens,
        clock,
    }
}

fn permissions() -> AccessTarget {
    AccessTarget::Permissions(
        PermissionsTarget::new(vec!["rest:orders:GET /api/orders".to_owned()]).unwrap(),
    )
}

fn document() -> AccessTarget {
    AccessTarget::GraphQl(GraphQlTarget::new("{ orders { id } }".to_owned(), None))
}

fn query(credential: &str, target: AccessTarget, minimum: Option<i64>) -> ValidateAccessQuery {
    ValidateAccessQuery {
        credential: Credential::new(credential.to_owned()),
        check: AccessCheck::new(
            ServiceName::new("orders").unwrap(),
            target,
            None,
            minimum.map(version),
        ),
    }
}

async fn single(scenario: &Scenario, query: ValidateAccessQuery) -> DecisionOutcome {
    scenario.single.handle(query).await.unwrap()
}

async fn batch(scenario: &Scenario, checks: Vec<BatchCheck>) -> Vec<DecisionOutcome> {
    scenario
        .batch
        .handle(ValidateAccessBatchQuery { checks })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_check_without_a_minimum_version_is_decided_on_the_snapshot() {
    let scenario = scenario();

    let outcome = single(&scenario, query("expired", permissions(), None)).await;

    assert_eq!(outcome.reason(), DecisionReason::TokenExpired);
}

#[tokio::test]
async fn a_minimum_version_the_snapshot_holds_is_decided() {
    let scenario = scenario();

    for held in [4, 5] {
        let outcome = single(&scenario, query("expired", permissions(), Some(held))).await;

        assert_eq!(outcome.reason(), DecisionReason::TokenExpired, "{held}");
    }
}

#[tokio::test]
async fn a_minimum_version_above_the_snapshot_is_the_deny_unavailable_not_an_error() {
    let scenario = scenario();

    let outcome = single(&scenario, query("expired", permissions(), Some(6))).await;

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(scenario.tokens.calls(), 0);
}

#[tokio::test]
async fn a_stale_snapshot_is_the_deny_unavailable() {
    let scenario = scenario();
    scenario.clock.advance(HARD + Duration::from_millis(1));

    let outcome = single(&scenario, query("expired", permissions(), None)).await;

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(scenario.tokens.calls(), 0);
}

#[tokio::test]
async fn a_graphql_document_is_the_deny_unavailable_because_the_snapshot_has_no_return_types() {
    let scenario = scenario();

    let outcome = single(&scenario, query("expired", document(), None)).await;

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
}

#[tokio::test]
async fn every_item_of_a_batch_is_admitted_on_its_own_in_request_order() {
    let scenario = scenario();

    let outcomes = batch(
        &scenario,
        vec![
            BatchCheck::Valid(query("expired", permissions(), None)),
            BatchCheck::Valid(query("expired", permissions(), Some(6))),
            BatchCheck::Malformed,
            BatchCheck::Valid(query("expired", document(), None)),
            BatchCheck::Valid(query("expired", permissions(), Some(5))),
        ],
    )
    .await;

    let reasons: Vec<_> = outcomes.iter().map(DecisionOutcome::reason).collect();
    assert_eq!(
        reasons,
        vec![
            DecisionReason::TokenExpired,
            DecisionReason::Unavailable,
            DecisionReason::MalformedOperation,
            DecisionReason::Unavailable,
            DecisionReason::TokenExpired,
        ]
    );
}

#[tokio::test]
async fn a_batch_resolves_each_credential_once() {
    let scenario = scenario();

    let outcomes = batch(
        &scenario,
        vec![
            BatchCheck::Valid(query("expired", permissions(), None)),
            BatchCheck::Valid(query("expired", permissions(), None)),
        ],
    )
    .await;

    assert_eq!(outcomes.len(), 2);
    assert_eq!(scenario.tokens.calls(), 1);
}

#[tokio::test]
async fn a_stale_snapshot_denies_every_item_of_a_batch() {
    let scenario = scenario();
    scenario.clock.advance(HARD + Duration::from_millis(1));

    let outcomes = batch(
        &scenario,
        vec![
            BatchCheck::Valid(query("expired", permissions(), None)),
            BatchCheck::Valid(query("expired", permissions(), None)),
        ],
    )
    .await;

    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.reason() == DecisionReason::Unavailable)
    );
}

fn seen_up_to(highest: i64) -> Arc<PolicyVersionBoard> {
    let board = Arc::new(PolicyVersionBoard::new());
    board.note_published(Some(version(5)));
    board.note_seen(version(highest));
    board
}

#[tokio::test]
async fn a_minimum_version_above_the_highest_seen_is_the_deny_unavailable_at_once() {
    let scenario = barred_scenario(&seen_up_to(5));

    let outcome = single(&scenario, query("expired", permissions(), Some(6))).await;

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(scenario.tokens.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_seen_minimum_version_that_is_not_published_in_time_is_the_deny_unavailable() {
    let scenario = barred_scenario(&seen_up_to(6));

    let outcome = single(&scenario, query("expired", permissions(), Some(6))).await;

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(scenario.tokens.calls(), 0);
}

#[tokio::test]
async fn a_minimum_version_the_snapshot_holds_is_decided_behind_the_barrier() {
    let scenario = barred_scenario(&seen_up_to(5));

    let outcomes = batch(
        &scenario,
        vec![
            BatchCheck::Valid(query("expired", permissions(), Some(5))),
            BatchCheck::Valid(query("expired", permissions(), Some(9))),
            BatchCheck::Valid(query("expired", permissions(), None)),
        ],
    )
    .await;

    let reasons: Vec<_> = outcomes.iter().map(DecisionOutcome::reason).collect();
    assert_eq!(
        reasons,
        vec![
            DecisionReason::TokenExpired,
            DecisionReason::Unavailable,
            DecisionReason::TokenExpired,
        ]
    );
}
