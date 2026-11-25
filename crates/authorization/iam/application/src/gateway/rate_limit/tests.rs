use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use iam_domain::{
    PolicyVersion, RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateLimitStore,
    RateLimitStoreError, RatePolicyId, RouteId, SubjectRef,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::local_rate_limiter::FakeLocalRateLimiter;
use test_support::rate_limit_store::FakeRateLimitStore;
use test_support::rate_policy::rate_policy_state;
use test_support::request_digester::FakeRequestDigester;

use super::{RateLimitGate, RateRequest, RateStage};

const TIMEOUT: Duration = Duration::from_millis(20);
const IP: &str = "203.0.113.7";

fn id(number: u128) -> RatePolicyId {
    RatePolicyId::from_uuid(Uuid::parse(&format!("00000000-0000-7000-8000-{number:012}")).unwrap())
}

fn route() -> RouteId {
    RouteId::from_uuid(Uuid::parse("00000000-0000-7000-8000-0000000000aa").unwrap())
}

fn subject() -> SubjectRef {
    SubjectRef::user(Uuid::parse("00000000-0000-7000-8000-0000000000bb").unwrap())
}

/// Policy 1 counts by IP, 2 by subject, 3 by route and 4 by subject and route.
fn snapshot() -> GatewaySnapshot {
    [
        (1, RateKeyKind::Ip),
        (2, RateKeyKind::Subject),
        (3, RateKeyKind::Route),
        (4, RateKeyKind::SubjectRoute),
    ]
    .into_iter()
    .fold(
        GatewaySnapshot::at(PolicyVersion::new(1).unwrap()),
        |snapshot, (number, kind)| {
            snapshot.with_rate_policy(rate_policy_state(id(number), kind, 10, 1, 0))
        },
    )
}

fn gate(
    store: Arc<dyn RateLimitStore>,
    local: &Arc<FakeLocalRateLimiter>,
) -> (RateLimitGate, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::new());
    let gate = RateLimitGate::new(
        store,
        Arc::<FakeLocalRateLimiter>::clone(local),
        Arc::new(FakeRequestDigester),
        Arc::<FakeBootClock>::clone(&clock),
        TIMEOUT,
    );
    (gate, clock)
}

fn request<'a>(
    snapshot: &'a GatewaySnapshot,
    policies: &'a [RatePolicyId],
    subject: Option<&'a SubjectRef>,
) -> RateRequest<'a> {
    RateRequest {
        snapshot,
        policies,
        route: route(),
        ip: Some(IP),
        subject,
    }
}

/// A store that never answers.
#[derive(Debug)]
struct SilentStore;

#[async_trait]
impl RateLimitStore for SilentStore {
    async fn check(
        &self,
        _policy_id: &RatePolicyId,
        _key: &RateKey,
        _rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        std::future::pending().await
    }
}

#[test]
fn the_anonymous_stage_counts_ip_and_route_and_the_authenticated_one_subject_keys() {
    assert!(RateStage::Anonymous.counts(RateKeyKind::Ip));
    assert!(RateStage::Anonymous.counts(RateKeyKind::Route));
    assert!(!RateStage::Anonymous.counts(RateKeyKind::Subject));
    assert!(!RateStage::Anonymous.counts(RateKeyKind::SubjectRoute));
    assert!(RateStage::Authenticated.counts(RateKeyKind::Subject));
    assert!(RateStage::Authenticated.counts(RateKeyKind::SubjectRoute));
    assert!(!RateStage::Authenticated.counts(RateKeyKind::Ip));
    assert!(!RateStage::Authenticated.counts(RateKeyKind::Route));
}

#[tokio::test]
async fn each_stage_asks_the_store_only_for_its_own_policies() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<FakeRateLimitStore>::clone(&store), &local);
    let snapshot = snapshot();
    let policies = [id(1), id(2), id(3), id(4)];
    let subject = subject();

    let anonymous = gate
        .check(RateStage::Anonymous, &request(&snapshot, &policies, None))
        .await;
    let before_authentication: Vec<RatePolicyId> =
        store.calls().iter().map(|call| call.policy_id).collect();
    let authenticated = gate
        .check(
            RateStage::Authenticated,
            &request(&snapshot, &policies, Some(&subject)),
        )
        .await;

    assert!(anonymous.is_admitted() && authenticated.is_admitted());
    assert_eq!(before_authentication, vec![id(1), id(3)]);
    let all: Vec<RatePolicyId> = store.calls().iter().map(|call| call.policy_id).collect();
    assert_eq!(all, vec![id(1), id(3), id(2), id(4)]);
}

#[tokio::test]
async fn a_route_without_rate_policies_never_reaches_the_store() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<FakeRateLimitStore>::clone(&store), &local);
    let snapshot = snapshot();
    let subject = subject();

    let first = gate
        .check(RateStage::Anonymous, &request(&snapshot, &[], None))
        .await;
    let second = gate
        .check(
            RateStage::Authenticated,
            &request(&snapshot, &[], Some(&subject)),
        )
        .await;

    assert!(first.is_admitted() && second.is_admitted());
    assert_eq!(store.calls().len(), 0);
    assert_eq!(local.fallback_calls().len(), 0);
}

#[tokio::test]
async fn the_first_policy_that_rejects_ends_the_check() {
    let reject = RateDecision::Reject {
        retry_after: Duration::from_secs(3),
    };
    let store = Arc::new(FakeRateLimitStore::new().with_decision(reject));
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<FakeRateLimitStore>::clone(&store), &local);
    let snapshot = snapshot();

    let decision = gate
        .check(
            RateStage::Anonymous,
            &request(&snapshot, &[id(1), id(3)], None),
        )
        .await;

    assert_eq!(decision, reject);
    assert_eq!(store.calls().len(), 1);
}

#[tokio::test]
async fn a_policy_the_snapshot_lacks_and_a_key_part_the_request_lacks_are_skipped() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<FakeRateLimitStore>::clone(&store), &local);
    let snapshot = snapshot();
    let policies = [id(99), id(1)];
    let mut without_address = request(&snapshot, &policies, None);
    without_address.ip = None;

    let decision = gate.check(RateStage::Anonymous, &without_address).await;
    let unauthenticated = gate
        .check(
            RateStage::Authenticated,
            &request(&snapshot, &[id(2)], None),
        )
        .await;

    assert!(decision.is_admitted() && unauthenticated.is_admitted());
    assert_eq!(store.calls().len(), 0);
}

#[tokio::test]
async fn a_store_that_fails_is_replaced_by_the_local_fallback_under_the_full_limit() {
    let store = Arc::new(FakeRateLimitStore::failing());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<FakeRateLimitStore>::clone(&store), &local);
    let snapshot = snapshot();

    let decision = gate
        .check(RateStage::Anonymous, &request(&snapshot, &[id(1)], None))
        .await;

    assert!(decision.is_admitted());
    let calls = local.fallback_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].policy_id, id(1));
    assert_eq!(
        calls[0].rule,
        RateDecisionRule::new(10, Duration::from_secs(1), 0)
    );
}

#[tokio::test(start_paused = true)]
async fn a_store_that_does_not_answer_in_time_is_replaced_by_the_local_fallback() {
    let local = Arc::new(FakeLocalRateLimiter::failing());
    let (gate, _clock) = gate(Arc::new(SilentStore), &local);
    let snapshot = snapshot();

    let decision = gate
        .check(RateStage::Anonymous, &request(&snapshot, &[id(3)], None))
        .await;

    assert_eq!(
        decision,
        RateDecision::Reject {
            retry_after: Duration::from_secs(1)
        }
    );
    assert_eq!(local.fallback_calls().len(), 1);
}

#[test]
fn the_guard_counts_the_client_address_and_admits_a_request_without_one() {
    let local = Arc::new(FakeLocalRateLimiter::failing());
    let (gate, _clock) = gate(Arc::new(FakeRateLimitStore::new()), &local);

    assert!(gate.check_guard(None).is_admitted());
    assert_eq!(local.guard_calls().len(), 0);
    assert!(!gate.check_guard(Some(IP)).is_admitted());
    let calls = local.guard_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind(), RateKeyKind::Ip);
    assert!(!calls[0].key_hash().contains(IP));
}
