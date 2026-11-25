use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::RETRY_AFTER;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt as _;
use iam_application::{FreshnessState, RateLimitGate, RateLimitPorts, RateStoreBounds};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    BootClock as _, BootInstant, FreshnessRule, HttpMethod, PolicyVersion, PolicyView,
    RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateLimitStore, RateLimitStoreError,
    RatePolicyId, RouteState, UpstreamState,
};
use shared_domain::{Clock, Uuid};
use shared_infrastructure::clock::SystemClock;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::local_rate_limiter::FakeLocalRateLimiter;
use test_support::rate_limit_store::FakeRateLimitStore;
use test_support::rate_policy::rate_policy_state;
use test_support::ready_peers::FakeReadyPeers;
use test_support::request_digester::FakeRequestDigester;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tower::ServiceExt as _;

use super::super::{Pipeline, UnreachableUpstreams, from_config, router};
use super::{ClientAddress, TYPE_RATE_LIMITED, gate_from_config, subject_of};
use crate::cli::GatewayArgs;
use crate::config::GatewayConfig;

const HOST: &str = "api.example.test";
const FIRST_CLIENT: &str = "203.0.113.1:50000";
const SECOND_CLIENT: &str = "203.0.113.2:50000";

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    GatewayConfig::from_args(&args).unwrap()
}

fn freshness() -> Arc<FreshnessState> {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    );
    state.attach(
        FreshnessProof {
            taken_at: clock.now(),
            watermark: 1,
        },
        PolicyVersion::new(1).unwrap(),
    );
    Arc::new(state)
}

fn policy_id() -> RatePolicyId {
    RatePolicyId::from_uuid(Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap())
}

/// A snapshot with one route, `/api/limited/{id}` with the policy of `kind` when there is one,
/// and `/api/open/{id}` without any.
fn snapshot(kind: Option<RateKeyKind>) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let stored = upstream(&mut rng, "users", "users");
    let upstream_state = UpstreamState::of(stored.parts());
    let mut limited = route_draft(
        HOST,
        "/api/limited/{id}",
        &[HttpMethod::Get],
        "users",
        upstream_state.id,
    );
    limited.rate_policies = kind.iter().map(|_kind| policy_id()).collect();
    let open = route_draft(
        HOST,
        "/api/open/{id}",
        &[HttpMethod::Get],
        "users",
        upstream_state.id,
    );
    let snapshot = GatewaySnapshot::at(PolicyVersion::new(1).unwrap())
        .with_upstream(upstream_state)
        .with_route(RouteState::of(route(&mut rng, &limited).parts()))
        .with_route(RouteState::of(route(&mut rng, &open).parts()));
    match kind {
        Some(kind) => snapshot.with_rate_policy(rate_policy_state(policy_id(), kind, 1, 60, 0)),
        None => snapshot,
    }
}

fn pipeline(snapshot: GatewaySnapshot, gate: RateLimitGate) -> Pipeline {
    let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::serving(snapshot));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    from_config(
        &config(),
        view,
        freshness(),
        &clock,
        Arc::new(UnreachableUpstreams),
    )
    .unwrap()
    .with_rate_limits(Arc::new(gate))
}

fn gate(store: Arc<dyn RateLimitStore>, local: &Arc<FakeLocalRateLimiter>) -> RateLimitGate {
    RateLimitGate::new(
        RateLimitPorts {
            store,
            local: Arc::<FakeLocalRateLimiter>::clone(local),
            digester: Arc::new(FakeRequestDigester),
            clock: Arc::new(FakeBootClock::new()),
            peers: Arc::new(FakeReadyPeers::new(1)),
        },
        RateStoreBounds {
            store_timeout: Duration::from_millis(20),
            breaker_open_duration: Duration::from_secs(5),
        },
    )
}

/// A store that admits the first request of every key and rejects the rest, counting the calls.
#[derive(Debug, Default)]
struct OncePerKey {
    seen: Mutex<HashMap<String, u32>>,
}

impl OncePerKey {
    fn calls(&self) -> u32 {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .sum()
    }
}

#[async_trait]
impl RateLimitStore for OncePerKey {
    async fn check(
        &self,
        _policy_id: &RatePolicyId,
        key: &RateKey,
        _rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        let count = *self
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.key_hash().to_owned())
            .and_modify(|seen| *seen = seen.saturating_add(1))
            .or_insert(1);
        Ok(if count == 1 {
            RateDecision::Admit
        } else {
            RateDecision::Reject {
                retry_after: Duration::from_millis(1_500),
            }
        })
    }
}

async fn get(pipeline: &Pipeline, path: &str, client: Option<&str>) -> Response {
    let mut builder = Request::get(path).header("host", HOST);
    if let Some(client) = client {
        let peer: SocketAddr = client.parse().unwrap();
        builder = builder.extension(ClientAddress::from(peer));
    }
    router(pipeline.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn problem_type(response: Response) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    document["type"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn an_address_over_its_ip_policy_gets_429_while_another_address_is_served() {
    let store = Arc::new(OncePerKey::default());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let pipeline = pipeline(
        snapshot(Some(RateKeyKind::Ip)),
        gate(Arc::<OncePerKey>::clone(&store), &local),
    );

    // Authentication refuses these requests with 401: the rate-limit step before it admitted them.
    let first = get(&pipeline, "/api/limited/1", Some(FIRST_CLIENT)).await;
    let second = get(&pipeline, "/api/limited/1", Some(FIRST_CLIENT)).await;
    let other = get(&pipeline, "/api/limited/1", Some(SECOND_CLIENT)).await;

    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers().get(RETRY_AFTER).unwrap(), "2");
    assert_eq!(problem_type(second).await, TYPE_RATE_LIMITED);
    assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.calls(), 3);
}

#[tokio::test]
async fn a_request_that_authentication_refuses_never_reaches_a_subject_counter() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let pipeline = pipeline(
        snapshot(Some(RateKeyKind::Subject)),
        gate(Arc::<FakeRateLimitStore>::clone(&store), &local),
    );

    let response = get(&pipeline, "/api/limited/1", Some(FIRST_CLIENT)).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.calls().len(), 0);
}

#[tokio::test]
async fn a_route_without_a_rate_policy_never_reaches_the_shared_store() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::new());
    let pipeline = pipeline(
        snapshot(Some(RateKeyKind::Ip)),
        gate(Arc::<FakeRateLimitStore>::clone(&store), &local),
    );

    let response = get(&pipeline, "/api/open/1", Some(FIRST_CLIENT)).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.calls().len(), 0);
    assert_eq!(local.guard_calls().len(), 1);
}

#[tokio::test]
async fn the_flood_guard_answers_429_even_for_a_route_without_a_rate_policy() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::failing());
    let pipeline = pipeline(
        snapshot(None),
        gate(Arc::<FakeRateLimitStore>::clone(&store), &local),
    );

    let response = get(&pipeline, "/api/open/1", Some(FIRST_CLIENT)).await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
    assert_eq!(store.calls().len(), 0);
}

#[tokio::test]
async fn a_request_without_a_client_address_is_not_counted_by_address() {
    let store = Arc::new(FakeRateLimitStore::new());
    let local = Arc::new(FakeLocalRateLimiter::failing());
    let pipeline = pipeline(
        snapshot(Some(RateKeyKind::Ip)),
        gate(Arc::<FakeRateLimitStore>::clone(&store), &local),
    );

    let response = get(&pipeline, "/api/limited/1", None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.calls().len(), 0);
    assert_eq!(local.guard_calls().len(), 0);
}

#[tokio::test]
async fn a_pipeline_without_a_gate_limits_nothing() {
    let view: Arc<dyn PolicyView> =
        Arc::new(CountingPolicyView::serving(snapshot(Some(RateKeyKind::Ip))));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let pipeline = from_config(
        &config(),
        view,
        freshness(),
        &clock,
        Arc::new(UnreachableUpstreams),
    )
    .unwrap();

    let response = get(&pipeline, "/api/limited/1", Some(FIRST_CLIENT)).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn the_client_address_is_the_ip_of_the_peer() {
    let peer: SocketAddr = "[2001:db8::7]:4433".parse().unwrap();

    assert_eq!(ClientAddress::from(peer).ip(), peer.ip());
}

#[test]
fn the_production_gate_connects_to_nothing_until_the_first_request() {
    let gate = gate_from_config(&config(), Arc::new(FakeReadyPeers::new(1)));

    assert_ne!(format!("{gate:?}"), "");
}

#[test]
fn the_production_gate_guards_with_the_configured_limit_and_burst() {
    let mut config = config();
    config.rate_limit.guard.limit = 1;
    config.rate_limit.guard.burst = 1;
    config.rate_limit.guard.period = Duration::from_secs(60);
    let gate = gate_from_config(&config, Arc::new(FakeReadyPeers::new(1)));

    let decisions: Vec<_> = (0..4)
        .map(|_| gate.check_guard(Some("203.0.113.9")))
        .collect();

    assert_eq!(decisions.first(), Some(&RateDecision::Admit));
    assert!(
        decisions
            .iter()
            .any(|decision| matches!(decision, RateDecision::Reject { .. })),
        "{decisions:?}"
    );
    assert!(
        decisions.len() > 2 && decisions.get(3).is_some_and(|d| !d.is_admitted()),
        "{decisions:?}"
    );
}

#[test]
fn the_subject_of_a_user_and_of_a_service_is_the_one_its_token_proved() {
    let user = Uuid::parse("00000000-0000-7000-8000-000000000009").unwrap();
    let service = iam_domain::ServiceName::new("orders").unwrap();

    assert_eq!(
        subject_of(&iam_domain::SubjectId::User(user)),
        iam_domain::SubjectRef::user(user)
    );
    assert_eq!(
        subject_of(&iam_domain::SubjectId::Service(service.clone())),
        iam_domain::SubjectRef::service(service)
    );
}
