use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use iam_domain::{
    EntityVersion, PolicyVersion, RateDecision, RateDecisionRule, RateFallback, RateKey,
    RateKeyKind, RateLimitStore, RateLimitStoreError, RatePolicyDraft, RatePolicyFields,
    RatePolicyId, RatePolicyState, RouteId, SubjectRef,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::local_rate_limiter::FakeLocalRateLimiter;
use test_support::log::LogRecorder;
use test_support::rate_limit_store::FakeRateLimitStore;
use test_support::rate_policy::rate_policy_state;
use test_support::ready_peers::FakeReadyPeers;
use test_support::request_digester::FakeRequestDigester;

use super::{RateLimitGate, RateLimitPorts, RateRequest, RateStage, RateStoreBounds};

const TIMEOUT: Duration = Duration::from_millis(20);
const OPEN: Duration = Duration::from_secs(5);
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
    gate_of_peers(store, local, Arc::new(FakeReadyPeers::new(1)))
}

fn gate_of_peers(
    store: Arc<dyn RateLimitStore>,
    local: &Arc<FakeLocalRateLimiter>,
    peers: Arc<FakeReadyPeers>,
) -> (RateLimitGate, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::new());
    let gate = RateLimitGate::new(
        RateLimitPorts {
            store,
            local: Arc::<FakeLocalRateLimiter>::clone(local),
            digester: Arc::new(FakeRequestDigester),
            clock: Arc::<FakeBootClock>::clone(&clock),
            peers,
        },
        RateStoreBounds {
            store_timeout: TIMEOUT,
            breaker_open_duration: OPEN,
        },
    );
    (gate, clock)
}

/// A store that fails while its switch is on and admits otherwise, and counts its calls.
#[derive(Debug, Default)]
struct SwitchStore {
    down: AtomicBool,
    calls: AtomicUsize,
}

impl SwitchStore {
    fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RateLimitStore for SwitchStore {
    async fn check(
        &self,
        _policy_id: &RatePolicyId,
        _key: &RateKey,
        _rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(RateLimitStoreError::Unavailable("down".into()));
        }
        Ok(RateDecision::Admit)
    }
}

fn full_fallback_snapshot(limit: i64) -> GatewaySnapshot {
    let fields = RatePolicyFields::new(RatePolicyDraft {
        name: "full".to_owned(),
        key_kind: RateKeyKind::Ip,
        limit,
        period_seconds: 1,
        burst: 0,
        fallback: RateFallback::Full,
    })
    .unwrap();
    GatewaySnapshot::at(PolicyVersion::new(1).unwrap()).with_rate_policy(RatePolicyState {
        id: id(1),
        fields,
        version: EntityVersion::INITIAL,
    })
}

async fn check_ip(gate: &RateLimitGate, snapshot: &GatewaySnapshot) -> RateDecision {
    gate.check(RateStage::Anonymous, &request(snapshot, &[id(1)], None))
        .await
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
#[derive(Debug, Default)]
struct SilentStore {
    calls: AtomicUsize,
}

#[async_trait]
impl RateLimitStore for SilentStore {
    async fn check(
        &self,
        _policy_id: &RatePolicyId,
        _key: &RateKey,
        _rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
    let (gate, _clock) = gate(Arc::new(SilentStore::default()), &local);
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

#[tokio::test]
async fn the_fifth_consecutive_failure_opens_the_breaker_and_the_local_limiter_decides_alone() {
    let store = Arc::new(SwitchStore::default());
    store.set_down(true);
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<SwitchStore>::clone(&store), &local);
    let snapshot = snapshot();

    for _ in 0..5 {
        assert!(check_ip(&gate, &snapshot).await.is_admitted());
    }
    assert_eq!(store.calls(), 5);
    for _ in 0..3 {
        assert!(check_ip(&gate, &snapshot).await.is_admitted());
    }

    assert_eq!(store.calls(), 5);
    assert_eq!(local.fallback_calls().len(), 8);
}

#[tokio::test]
async fn an_answer_between_failures_keeps_the_breaker_closed() {
    let store = Arc::new(SwitchStore::default());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<SwitchStore>::clone(&store), &local);
    let snapshot = snapshot();

    for _ in 0..4 {
        store.set_down(true);
        check_ip(&gate, &snapshot).await;
    }
    store.set_down(false);
    check_ip(&gate, &snapshot).await;
    store.set_down(true);
    for _ in 0..4 {
        check_ip(&gate, &snapshot).await;
    }

    assert_eq!(store.calls(), 9);
}

#[tokio::test]
async fn after_the_open_duration_one_probe_goes_through_and_a_healthy_store_closes_the_breaker() {
    let store = Arc::new(SwitchStore::default());
    store.set_down(true);
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, clock) = gate(Arc::<SwitchStore>::clone(&store), &local);
    let snapshot = snapshot();
    for _ in 0..5 {
        check_ip(&gate, &snapshot).await;
    }
    store.set_down(false);

    clock.advance(OPEN.saturating_sub(Duration::from_millis(1)));
    check_ip(&gate, &snapshot).await;
    assert_eq!(store.calls(), 5);
    clock.advance(Duration::from_millis(1));
    check_ip(&gate, &snapshot).await;
    assert_eq!(store.calls(), 6);
    check_ip(&gate, &snapshot).await;
    check_ip(&gate, &snapshot).await;

    assert_eq!(store.calls(), 8);
    assert_eq!(local.fallback_calls().len(), 6);
}

#[tokio::test]
async fn a_probe_that_fails_keeps_the_local_limiter_for_another_open_duration() {
    let store = Arc::new(SwitchStore::default());
    store.set_down(true);
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, clock) = gate(Arc::<SwitchStore>::clone(&store), &local);
    let snapshot = snapshot();
    for _ in 0..5 {
        check_ip(&gate, &snapshot).await;
    }

    clock.advance(OPEN);
    check_ip(&gate, &snapshot).await;
    assert_eq!(store.calls(), 6);
    check_ip(&gate, &snapshot).await;
    clock.advance(OPEN);
    check_ip(&gate, &snapshot).await;

    assert_eq!(store.calls(), 7);
}

#[tokio::test(start_paused = true)]
async fn five_timeouts_open_the_breaker_like_five_failures() {
    let store = Arc::new(SilentStore::default());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<SilentStore>::clone(&store), &local);
    let snapshot = snapshot();

    for _ in 0..6 {
        assert!(check_ip(&gate, &snapshot).await.is_admitted());
    }

    assert_eq!(store.calls.load(Ordering::SeqCst), 5);
    assert_eq!(local.fallback_calls().len(), 6);
}

#[tokio::test]
async fn the_fallback_limit_is_divided_among_the_ready_pods_unless_the_policy_says_full() {
    let local = Arc::new(FakeLocalRateLimiter::new());
    let peers = Arc::new(FakeReadyPeers::new(3));
    let (gate, _clock) = gate_of_peers(
        Arc::new(FakeRateLimitStore::failing()),
        &local,
        Arc::<FakeReadyPeers>::clone(&peers),
    );
    let divided = GatewaySnapshot::at(PolicyVersion::new(1).unwrap())
        .with_rate_policy(rate_policy_state(id(1), RateKeyKind::Ip, 30, 1, 0));
    let full = full_fallback_snapshot(30);

    check_ip(&gate, &divided).await;
    check_ip(&gate, &full).await;
    peers.set(0);
    check_ip(&gate, &divided).await;

    let rules: Vec<RateDecisionRule> = local
        .fallback_calls()
        .iter()
        .map(|call| call.rule)
        .collect();
    let period = Duration::from_secs(1);
    assert_eq!(
        rules,
        vec![
            RateDecisionRule::new(10, period, 0),
            RateDecisionRule::new(30, period, 0),
            RateDecisionRule::new(30, period, 0),
        ]
    );
}

#[tokio::test]
async fn a_request_decided_while_the_breaker_is_open_uses_the_conservative_limit_too() {
    let store = Arc::new(SwitchStore::default());
    store.set_down(true);
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate_of_peers(
        Arc::<SwitchStore>::clone(&store),
        &local,
        Arc::new(FakeReadyPeers::new(2)),
    );
    let snapshot = GatewaySnapshot::at(PolicyVersion::new(1).unwrap())
        .with_rate_policy(rate_policy_state(id(1), RateKeyKind::Ip, 30, 1, 0));
    for _ in 0..6 {
        check_ip(&gate, &snapshot).await;
    }

    let last = local.fallback_calls().pop().unwrap();

    assert_eq!(store.calls(), 5);
    assert_eq!(
        last.rule,
        RateDecisionRule::new(15, Duration::from_secs(1), 0)
    );
}

#[tokio::test]
async fn every_degraded_decision_and_the_opening_of_the_breaker_are_metric_events() {
    let (recorder, _guard) = LogRecorder::install();
    let store = Arc::new(SwitchStore::default());
    store.set_down(true);
    let local = Arc::new(FakeLocalRateLimiter::new());
    let (gate, _clock) = gate(Arc::<SwitchStore>::clone(&store), &local);
    let snapshot = snapshot();

    for _ in 0..6 {
        check_ip(&gate, &snapshot).await;
    }

    let reasons: Vec<String> = recorder
        .lines()
        .iter()
        .filter(|line| line.field("metric") == Some("rate_limit_store_degraded"))
        .filter_map(|line| line.field("reason").map(str::to_owned))
        .collect();
    let mut expected = vec!["unavailable"; 5];
    expected.extend(["breaker_opened", "breaker_open"]);
    assert_eq!(reasons, expected);
}
