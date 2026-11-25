//! The rate-limit step of the pipeline against the compose Valkey (Story 12.2, FR-65): two gateways
//! in one process share one Valkey, so a quota holds across the fleet. Story 12.3 adds the fault
//! proxy in front of the Valkey: slow, paused and stopped Valkey, the breaker and the conservative
//! local limit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_application::{
    FreshnessState, RateLimitGate, RateLimitPorts, RateStoreBounds, RequestAuthorizer,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock, BootInstant, CatalogueEntryState, CompiledRoleSet, EntityVersion, ForwardError,
    FreshnessRule, GrantStatus, HttpMethod, LocalRateLimiter, PermissionGrant, PolicyVersion,
    PolicyView, RateDecisionRule, RateFallback, RateKey, RateKeyKind, RateKeyParts, RateLimitStore,
    RatePolicyDraft, RatePolicyFields, RatePolicyId, RatePolicyState, ReadyPeers, RequestDigester,
    RevocationView, RoleId, RouteState, ServiceName, SessionId, SubjectId, SubjectRef, TokenId,
    TokenMemo, TokenRejection, TokenRepository, UpstreamForwarder, UpstreamState, UpstreamTarget,
};
use iam_infrastructure::{
    BucketLocalRateLimiter, CachingTokenRepository, LinuxBootClock, MokaTokenMemo,
    Sha256RequestDigester, SnapshotRevocationView, TokenMemoSettings, ValkeyEndpoint,
    ValkeyRateLimitStore,
};
use service::bootstrap::gateway::pipeline::{
    ClientAddress, Pipeline, TYPE_RATE_LIMITED, UnauditedCommands, router,
};
use shared_domain::{Clock, CommandBus, Uuid, UuidGenerator as _};
use shared_infrastructure::id::UuidV7Generator;
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::log::LogRecorder;
use test_support::ready_peers::FakeReadyPeers;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt as _;

const HOST: &str = "api.example.test";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const OTHER_USER: &str = "7a1c5e3b-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const NOW: u64 = 1_800_000_000;
const GOOD: &str = "good.token.value";
const OTHER: &str = "other.token.value";
const INVALID: &str = "invalid.token.value";
const STORE_TIMEOUT: Duration = Duration::from_millis(50);

#[expect(
    clippy::disallowed_methods,
    reason = "the test stack is described by the environment"
)]
fn stack_variable(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run the tests through `make`"))
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn token(user: &str, session: &str) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(user).unwrap()),
        session: Some(SessionId::new(session).unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 900),
    })
}

fn verifier() -> FakeAccessTokenVerifier {
    FakeAccessTokenVerifier::new()
        .accepting(GOOD, token(USER, "session-1"))
        .accepting(OTHER, token(OTHER_USER, "session-2"))
        .rejecting(INVALID, TokenRejection::Invalid)
}

fn entry(key: &str) -> CatalogueEntryState {
    CatalogueEntryState::untyped(key.to_owned(), [false, false])
}

fn policy_id() -> RatePolicyId {
    RatePolicyId::from_uuid(UuidV7Generator.generate())
}

/// The numbers of one rate policy of a test.
#[derive(Debug, Clone, Copy)]
struct Policy {
    id: RatePolicyId,
    kind: RateKeyKind,
    limit: i64,
    period_seconds: i64,
    burst: i64,
}

/// A snapshot of one service `users` with the routes `GET /api/limited/{id}`, which carries
/// `policies`, and `GET /api/open/{id}`, which carries none. Both users hold the keys of both.
fn snapshot(policies: &[Policy]) -> GatewaySnapshot {
    snapshot_of(policies, RateFallback::Divided)
}

/// The rate policy state of `policy`, falling back as `fallback` says.
fn state_of(policy: &Policy, fallback: RateFallback) -> RatePolicyState {
    RatePolicyState {
        id: policy.id,
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "limit".to_owned(),
            key_kind: policy.kind,
            limit: policy.limit,
            period_seconds: policy.period_seconds,
            burst: policy.burst,
            fallback,
        })
        .unwrap(),
        version: EntityVersion::INITIAL,
    }
}

/// The snapshot of [`snapshot`] whose rate policies fall back as `fallback` says.
fn snapshot_of(policies: &[Policy], fallback: RateFallback) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let users = UpstreamState::of(upstream(&mut rng, "users", "users").parts());
    let role = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile(
        [
            "rest:users:GET /api/limited/{}",
            "rest:users:GET /api/open/{}",
        ]
        .map(|key| (PermissionGrant::parse(key).unwrap(), GrantStatus::Active)),
    );
    let mut limited = route_draft(
        HOST,
        "/api/limited/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    limited.rate_policies = policies.iter().map(|policy| policy.id).collect();
    let open = route_draft(
        HOST,
        "/api/open/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    let assignment = || {
        vec![AssignmentState {
            role,
            scope: AssignmentScope::Global,
            expires_at_micros: None,
        }]
    };
    let snapshot = GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(&mut rng, &limited).parts()))
        .with_route(RouteState::of(route(&mut rng, &open).parts()))
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![
                entry("rest:users:GET /api/limited/{}"),
                entry("rest:users:GET /api/open/{}"),
            ],
        )
        .with_assignments(SubjectRef::user(Uuid::parse(USER).unwrap()), assignment())
        .with_assignments(
            SubjectRef::user(Uuid::parse(OTHER_USER).unwrap()),
            assignment(),
        )
        .with_role_set(role, granted);
    policies.iter().fold(snapshot, |snapshot, policy| {
        snapshot.with_rate_policy(state_of(policy, fallback))
    })
}

/// A forwarder that answers 200 to every request.
#[derive(Debug)]
struct Accepting;

#[async_trait::async_trait]
impl UpstreamForwarder for Accepting {
    type Request = Request<Body>;
    type Response = Response;

    async fn forward(
        &self,
        _target: UpstreamTarget,
        _request: Request<Body>,
    ) -> Result<Response, ForwardError> {
        Ok(StatusCode::OK.into_response())
    }
}

/// A store already connected and with the script loaded, so that the first request of a test does
/// not spend its `RATE_LIMIT_STORE_TIMEOUT` on setting up the connection.
async fn warm_store(url: &str) -> Arc<ValkeyRateLimitStore> {
    let store = Arc::new(ValkeyRateLimitStore::new(
        ValkeyEndpoint::parse(url).unwrap(),
    ));
    let parts = RateKeyParts {
        ip: Some("198.51.100.1"),
        ..RateKeyParts::default()
    };
    let key = RateKey::new(RateKeyKind::Ip, &parts, &Sha256RequestDigester).unwrap();
    let rule = RateDecisionRule::new(1, Duration::from_secs(1), 0);
    store.check(&policy_id(), &key, &rule).await.unwrap();
    store
}

/// What the gate of a pod is wired with besides the store.
struct Wiring {
    boot_clock: Arc<dyn BootClock>,
    peers: Arc<dyn ReadyPeers>,
    store_timeout: Duration,
    breaker_open_duration: Duration,
}

impl Wiring {
    /// The wiring of a healthy fleet: the real boot clock and a single ready pod.
    fn live() -> Self {
        Self {
            boot_clock: Arc::new(LinuxBootClock),
            peers: Arc::new(FakeReadyPeers::new(1)),
            store_timeout: STORE_TIMEOUT,
            breaker_open_duration: Duration::from_secs(5),
        }
    }
}

/// One gateway pod: its own pipeline, store connection and local limiter over the Valkey at `url`.
async fn pod(url: &str, snapshot: &GatewaySnapshot, warm: bool) -> Router {
    pod_with(url, snapshot, warm, Wiring::live()).await
}

/// One gateway pod over the Valkey at `url`, its gate wired by `wiring`.
async fn pod_with(url: &str, snapshot: &GatewaySnapshot, warm: bool, wiring: Wiring) -> Router {
    let view = Arc::new(CountingPolicyView::serving(snapshot.clone()));
    let boot = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let freshness = Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&boot),
    ));
    freshness.attach(
        FreshnessProof {
            taken_at: boot.now(),
            watermark: 1,
        },
        PolicyVersion::new(7).unwrap(),
    );
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let policy: Arc<dyn PolicyView> = Arc::<CountingPolicyView>::clone(&view);
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(verifier());
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(5),
        },
        Arc::clone(&clock),
    ));
    let revocations: Arc<dyn RevocationView> =
        Arc::new(SnapshotRevocationView::new(Arc::clone(&policy)));
    let tokens = Arc::new(CachingTokenRepository::new(verifier, memo, revocations));
    let token_port: Arc<dyn TokenRepository> = Arc::<CachingTokenRepository>::clone(&tokens);
    let commands: Arc<dyn CommandBus> = Arc::new(UnauditedCommands);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(&clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    let boot_clock = wiring.boot_clock;
    let local: Arc<dyn LocalRateLimiter> = Arc::new(BucketLocalRateLimiter::new(
        Arc::clone(&boot_clock),
        RateDecisionRule::new(2_000, Duration::from_secs(1), 2_000),
        1_000,
    ));
    let digester: Arc<dyn RequestDigester> = Arc::new(Sha256RequestDigester);
    let store: Arc<dyn RateLimitStore> = if warm {
        warm_store(url).await
    } else {
        Arc::new(ValkeyRateLimitStore::new(
            ValkeyEndpoint::parse(url).unwrap(),
        ))
    };
    let gate = RateLimitGate::new(
        RateLimitPorts {
            store,
            local,
            digester,
            clock: boot_clock,
            peers: wiring.peers,
        },
        RateStoreBounds {
            store_timeout: wiring.store_timeout,
            breaker_open_duration: wiring.breaker_open_duration,
        },
    );
    let pipeline = Pipeline::new(
        policy,
        freshness,
        tokens,
        Arc::new(authorizer),
        Arc::new(Accepting),
    )
    .with_rate_limits(Arc::new(gate));
    router(pipeline)
}

fn request(path: &str, token: Option<&str>, client: Option<&str>) -> Request<Body> {
    let mut builder = Request::get(path).header("host", HOST);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(client) = client {
        let peer: SocketAddr = client.parse().unwrap();
        builder = builder.extension(ClientAddress::from(peer));
    }
    builder.body(Body::empty()).unwrap()
}

async fn send(pod: &Router, request: Request<Body>) -> Response {
    pod.clone().oneshot(request).await.unwrap()
}

async fn problem_type(response: Response) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    document["type"].as_str().unwrap().to_owned()
}

async fn valkey() -> redis::aio::MultiplexedConnection {
    redis::Client::open(stack_variable("RATE_LIMIT_STORE_URL"))
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

#[tokio::test]
async fn thirty_requests_spread_over_two_gateways_admit_exactly_the_limit() {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let policy = Policy {
        id: policy_id(),
        kind: RateKeyKind::Route,
        limit: 10,
        period_seconds: 1,
        burst: 0,
    };
    let snapshot = snapshot(&[policy]);
    let pods = [
        pod(&url, &snapshot, true).await,
        pod(&url, &snapshot, true).await,
    ];
    let mut admitted = 0;
    let mut rejected = 0;

    // Ten rounds of three requests, 110 ms apart (the emission interval is 100 ms), the last round
    // inside the first second: each round admits its first request and rejects the other two.
    for round in 0..10_usize {
        for turn in 0..3_usize {
            let pod = &pods[(round + turn) % 2];
            let response = send(pod, request("/api/limited/1", Some(GOOD), None)).await;
            match response.status() {
                StatusCode::OK => admitted += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    rejected += 1;
                    assert!(response.headers().contains_key(RETRY_AFTER));
                    assert_eq!(problem_type(response).await, TYPE_RATE_LIMITED);
                }
                other => panic!("unexpected status {other}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(110)).await;
    }

    assert_eq!((admitted, rejected), (10, 20));
}

#[tokio::test]
async fn each_subject_has_its_own_quota_and_a_refused_token_consumes_none() {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let policy = Policy {
        id: policy_id(),
        kind: RateKeyKind::Subject,
        limit: 1,
        period_seconds: 60,
        burst: 0,
    };
    let pods = [pod(&url, &snapshot(&[policy]), true).await];
    let pod = &pods[0];
    let path = "/api/limited/1";

    for _ in 0..3 {
        let refused = send(pod, request(path, Some(INVALID), Some("203.0.113.30:4000"))).await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    }
    let first = send(pod, request(path, Some(GOOD), None)).await.status();
    let again = send(pod, request(path, Some(GOOD), None)).await;
    let other = send(pod, request(path, Some(OTHER), None)).await.status();
    let other_again = send(pod, request(path, Some(OTHER), None)).await.status();

    assert_eq!(first, StatusCode::OK);
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(problem_type(again).await, TYPE_RATE_LIMITED);
    assert_eq!(other, StatusCode::OK);
    assert_eq!(other_again, StatusCode::TOO_MANY_REQUESTS);
    assert_keys_of(
        policy.id,
        2,
        &[USER, OTHER_USER, GOOD, OTHER, INVALID, "203.0.113.30"],
    )
    .await;
}

/// The keys of `policy` in Valkey: `expected` of them, each `rl:<policyId>:<keyHash>` with an
/// expiry, and none naming one of `forbidden`.
async fn assert_keys_of(policy: RatePolicyId, expected: usize, forbidden: &[&str]) {
    let mut connection = valkey().await;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("rl:{policy}:*"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), expected, "keys: {keys:?}");
    for key in keys {
        let hash = key.strip_prefix(&format!("rl:{policy}:")).unwrap();
        assert_eq!(hash.len(), 64, "key {key}");
        assert!(
            hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "key {key}"
        );
        assert!(
            forbidden.iter().all(|value| !key.contains(value)),
            "key {key}"
        );
        let expiry: i64 = redis::cmd("PTTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(expiry > 0, "key {key} has no expiry");
    }
}

#[tokio::test]
async fn every_rate_key_in_valkey_has_the_form_policy_and_hash_with_an_expiry() {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let policy = Policy {
        id: policy_id(),
        kind: RateKeyKind::Ip,
        limit: 100,
        period_seconds: 60,
        burst: 0,
    };
    let pod = pod(&url, &snapshot(&[policy]), true).await;
    for client in ["203.0.113.40:1", "203.0.113.41:1"] {
        send(&pod, request("/api/limited/1", Some(GOOD), Some(client))).await;
    }
    let mut connection = valkey().await;

    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("rl:*")
        .query_async(&mut connection)
        .await
        .unwrap();

    assert!(keys.len() >= 2);
    for key in keys {
        let mut parts = key.splitn(3, ':');
        assert_eq!(parts.next(), Some("rl"), "key {key}");
        assert!(Uuid::parse(parts.next().unwrap()).is_ok(), "key {key}");
        let hash = parts.next().unwrap();
        assert!(hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let expiry: i64 = redis::cmd("PTTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(expiry > 0 || expiry == -2, "key {key} has no expiry");
        assert!(!key.contains("203.0.113"), "key {key}");
    }
}

/// A TCP proxy in front of Valkey that counts the connections it accepts.
struct CountingProxy {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
}

#[expect(
    clippy::disallowed_methods,
    reason = "a test puts a counting proxy on a free loopback port in front of the compose Valkey"
)]
async fn counting_proxy(target: String) -> CountingProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _peer)) = listener.accept().await else {
                break;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            let target = target.clone();
            tokio::spawn(async move {
                if let Ok(mut server) = TcpStream::connect(target).await {
                    drop(copy_bidirectional(&mut client, &mut server).await);
                }
            });
        }
    });
    CountingProxy {
        address,
        connections,
    }
}

#[tokio::test]
async fn a_route_without_a_rate_policy_sends_valkey_no_command() {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let target = url
        .strip_prefix("redis://")
        .unwrap()
        .trim_end_matches('/')
        .to_owned();
    let proxy = counting_proxy(target).await;
    let policy = Policy {
        id: policy_id(),
        kind: RateKeyKind::Route,
        limit: 100,
        period_seconds: 60,
        burst: 0,
    };
    let snapshot = snapshot(&[policy]);
    let through_proxy = pod(&format!("redis://{}", proxy.address), &snapshot, false).await;

    for _ in 0..5 {
        let response = send(&through_proxy, request("/api/open/1", Some(GOOD), None)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(proxy.connections.load(Ordering::SeqCst), 0);

    let limited = send(&through_proxy, request("/api/limited/1", Some(GOOD), None)).await;
    assert!(
        limited.status() == StatusCode::OK || limited.status() == StatusCode::TOO_MANY_REQUESTS
    );
    assert!(proxy.connections.load(Ordering::SeqCst) >= 1);
}

// Story 12.3: the shared store degrades; the breaker, the conservative local limit and the
// guarantee that the limiter never answers 503 and never changes who is authorized.

const PASSING: u8 = 0;
const SLOW: u8 = 1;
const PAUSED: u8 = 2;
const STOPPED: u8 = 3;

/// A TCP proxy in front of the compose Valkey that a test switches between passing traffic,
/// delaying it, holding it (a paused container) and refusing it (a stopped one), for connections
/// that are already open as well as for new ones.
struct FaultProxy {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    delay_millis: Arc<AtomicU64>,
    commands: Arc<AtomicUsize>,
}

impl FaultProxy {
    fn url(&self) -> String {
        format!("redis://{}", self.address)
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    /// Delays every chunk of traffic by `delay` while the mode is slow.
    fn slow_by(&self, delay: Duration) {
        self.delay_millis
            .store(u64::try_from(delay.as_millis()).unwrap(), Ordering::SeqCst);
        self.set(SLOW);
    }

    /// The chunks of commands the proxy has received from gateways so far.
    fn commands(&self) -> usize {
        self.commands.load(Ordering::SeqCst)
    }
}

/// Copies `from` to `to` chunk by chunk, applying the mode of the proxy to each chunk.
async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    faults: (Arc<AtomicU8>, Arc<AtomicU64>),
    commands: Option<Arc<AtomicUsize>>,
) {
    let (mode, delay_millis) = faults;
    let mut buffer = [0_u8; 4096];
    while let Ok(count) = from.read(&mut buffer).await {
        if count == 0 {
            break;
        }
        if let Some(commands) = &commands {
            commands.fetch_add(1, Ordering::SeqCst);
        }
        match mode.load(Ordering::SeqCst) {
            STOPPED => break,
            PAUSED => std::future::pending::<()>().await,
            SLOW => {
                tokio::time::sleep(Duration::from_millis(delay_millis.load(Ordering::SeqCst)))
                    .await;
            }
            _ => {}
        }
        if to.write_all(&buffer[..count]).await.is_err() {
            break;
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "a test puts a fault proxy on a free loopback port in front of the compose Valkey"
)]
async fn fault_proxy() -> FaultProxy {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let target = url
        .strip_prefix("redis://")
        .unwrap()
        .trim_end_matches('/')
        .to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = FaultProxy {
        address: listener.local_addr().unwrap(),
        mode: Arc::new(AtomicU8::new(PASSING)),
        delay_millis: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(AtomicUsize::new(0)),
    };
    let faults = (Arc::clone(&proxy.mode), Arc::clone(&proxy.delay_millis));
    let commands = Arc::clone(&proxy.commands);
    tokio::spawn(async move {
        loop {
            let Ok((client, _peer)) = listener.accept().await else {
                break;
            };
            if faults.0.load(Ordering::SeqCst) == STOPPED {
                continue;
            }
            let Ok(server) = TcpStream::connect(target.clone()).await else {
                continue;
            };
            let (client_read, client_write) = client.into_split();
            let (server_read, server_write) = server.into_split();
            tokio::spawn(pump(
                client_read,
                server_write,
                faults.clone(),
                Some(Arc::clone(&commands)),
            ));
            tokio::spawn(pump(server_read, client_write, faults.clone(), None));
        }
    });
    proxy
}

/// A policy that counts by route with `limit` per second and no burst.
fn route_policy(limit: i64) -> Policy {
    route_policy_with_burst(limit, 0)
}

/// A route policy whose burst lets a test send several requests at one instant of the controlled
/// clock, which a policy without a burst answers 429 from its second request on.
fn route_policy_with_burst(limit: i64, burst: i64) -> Policy {
    Policy {
        id: policy_id(),
        kind: RateKeyKind::Route,
        limit,
        period_seconds: 1,
        burst,
    }
}

/// A pod over `proxy` with a controlled boot clock and `ready` ready pods, whose store connection
/// is already set up through the passing proxy.
async fn degraded_pod(
    proxy: &FaultProxy,
    snapshot: &GatewaySnapshot,
    ready: u32,
    open: Duration,
) -> (Router, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(1_000),
    )));
    let wiring = Wiring {
        boot_clock: Arc::<FakeBootClock>::clone(&clock),
        peers: Arc::new(FakeReadyPeers::new(ready)),
        store_timeout: Duration::from_millis(10),
        breaker_open_duration: open,
    };
    (pod_with(&proxy.url(), snapshot, true, wiring).await, clock)
}

/// Waits until the slowed proxy has passed on the commands that timed out, so that none of them is
/// counted, or delays the answer of a later call, after the test has read the command count.
async fn drain() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}

async fn status_of(pod: &Router, token: &str) -> StatusCode {
    send(pod, request("/api/limited/1", Some(token), None))
        .await
        .status()
}

#[tokio::test]
async fn a_slow_valkey_times_every_call_out_and_five_timeouts_open_the_breaker() {
    let (recorder, _guard) = LogRecorder::install();
    let proxy = fault_proxy().await;
    let snapshot = snapshot(&[route_policy_with_burst(1_000, 20)]);
    let (pod, _clock) = degraded_pod(&proxy, &snapshot, 1, Duration::from_secs(5)).await;
    proxy.slow_by(Duration::from_millis(20));

    for _ in 0..5 {
        assert_eq!(status_of(&pod, GOOD).await, StatusCode::OK);
    }
    drain().await;
    let reached = proxy.commands();
    for _ in 0..5 {
        assert_eq!(status_of(&pod, GOOD).await, StatusCode::OK);
    }

    assert_eq!(
        proxy.commands(),
        reached,
        "an open breaker sends no command"
    );
    let reasons: Vec<String> = recorder
        .lines()
        .iter()
        .filter(|line| line.field("metric") == Some("rate_limit_store_degraded"))
        .filter_map(|line| line.field("reason").map(str::to_owned))
        .collect();
    assert_eq!(
        reasons
            .iter()
            .filter(|reason| *reason == "timed_out")
            .count(),
        5
    );
    assert_eq!(
        reasons
            .iter()
            .filter(|reason| *reason == "breaker_opened")
            .count(),
        1
    );
    assert_eq!(
        reasons
            .iter()
            .filter(|reason| *reason == "breaker_open")
            .count(),
        5
    );
}

#[tokio::test]
async fn after_the_open_duration_one_probe_closes_the_breaker_and_exact_counting_resumes() {
    let proxy = fault_proxy().await;
    let snapshot = snapshot(&[route_policy_with_burst(1_000, 20)]);
    let open = Duration::from_secs(5);
    let (pod, clock) = degraded_pod(&proxy, &snapshot, 1, open).await;
    proxy.slow_by(Duration::from_millis(20));
    for _ in 0..6 {
        status_of(&pod, GOOD).await;
    }
    drain().await;
    let while_open = proxy.commands();
    proxy.set(PASSING);

    clock.advance(open.saturating_sub(Duration::from_millis(1)));
    status_of(&pod, GOOD).await;
    assert_eq!(proxy.commands(), while_open, "the breaker is still open");
    clock.advance(Duration::from_millis(1));
    let probe = status_of(&pod, GOOD).await;
    let after_probe = proxy.commands();
    let counted = status_of(&pod, GOOD).await;

    assert_eq!(probe, StatusCode::OK);
    assert_eq!(counted, StatusCode::OK);
    assert!(after_probe > while_open, "one probe call was made");
    assert!(proxy.commands() > after_probe, "exact counting resumed");
}

/// Sends 30 requests 33 ms of the controlled clock apart and counts the admitted ones.
async fn admitted_in_one_second(pod: &Router, clock: &FakeBootClock) -> usize {
    let mut admitted = 0_usize;
    for _ in 0..30 {
        match status_of(pod, GOOD).await {
            StatusCode::OK => admitted = admitted.saturating_add(1),
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected status {other}"),
        }
        clock.advance(Duration::from_millis(33));
    }
    admitted
}

#[tokio::test]
async fn with_valkey_paused_a_divided_policy_admits_a_third_of_its_limit_on_one_of_three_pods() {
    let proxy = fault_proxy().await;
    let snapshot = snapshot(&[route_policy(30)]);
    let (pod, clock) = degraded_pod(&proxy, &snapshot, 3, Duration::from_secs(60)).await;
    proxy.set(PAUSED);

    let admitted = admitted_in_one_second(&pod, &clock).await;

    assert!((7..=10).contains(&admitted), "admitted {admitted}");
}

#[tokio::test]
async fn with_valkey_stopped_a_full_policy_admits_up_to_its_whole_limit_on_one_pod() {
    let proxy = fault_proxy().await;
    let snapshot = snapshot_of(&[route_policy(30)], RateFallback::Full);
    let (pod, clock) = degraded_pod(&proxy, &snapshot, 3, Duration::from_secs(60)).await;
    proxy.set(STOPPED);

    let admitted = admitted_in_one_second(&pod, &clock).await;

    assert!((11..=30).contains(&admitted), "admitted {admitted}");
}

#[tokio::test]
async fn with_valkey_down_the_limiter_never_answers_503_and_never_changes_who_is_authorized() {
    let proxy = fault_proxy().await;
    let snapshot = snapshot(&[route_policy_with_burst(3_000, 3_000)]).with_assignments(
        SubjectRef::user(Uuid::parse(OTHER_USER).unwrap()),
        Vec::new(),
    );
    let (pod, clock) = degraded_pod(&proxy, &snapshot, 3, Duration::from_secs(60)).await;
    proxy.set(STOPPED);

    for _ in 0..20 {
        let with_key = status_of(&pod, GOOD).await;
        let without_key = status_of(&pod, OTHER).await;
        let refused = status_of(&pod, INVALID).await;

        assert!(
            with_key == StatusCode::OK || with_key == StatusCode::TOO_MANY_REQUESTS,
            "{with_key}"
        );
        assert_eq!(without_key, StatusCode::FORBIDDEN);
        assert_eq!(refused, StatusCode::UNAUTHORIZED);
        clock.advance(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn residence_time_with_valkey_down_is_reported_next_to_the_target_of_nfr_42() {
    let proxy = fault_proxy().await;
    let snapshot = snapshot(&[route_policy(1_000_000)]);
    let (pod, _clock) = degraded_pod(&proxy, &snapshot, 1, Duration::from_secs(60)).await;
    proxy.set(STOPPED);
    let mut residences = Vec::new();

    for _ in 0..200 {
        let started = tokio::time::Instant::now();
        let status = status_of(&pod, GOOD).await;
        residences.push(started.elapsed());
        assert_ne!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    residences.sort();
    let p99 = residences[residences.len() * 99 / 100];

    // A measurement of this compose host, not a gate: NFR-42 asks for NFR-33 (p99 of 2 ms on a
    // route with a Valkey policy) plus RATE_LIMIT_STORE_TIMEOUT (10 ms here).
    println!(
        "valkey down: residence p99 {p99:?} against the NFR-42 target of {:?} (NFR-33 2 ms plus 10 ms store timeout)",
        Duration::from_millis(12)
    );
}

#[tokio::test]
async fn two_gateways_over_a_healthy_valkey_never_admit_more_than_limit_plus_burst_per_period() {
    let url = stack_variable("RATE_LIMIT_STORE_URL");
    let policy = Policy {
        id: policy_id(),
        kind: RateKeyKind::Route,
        limit: 10,
        period_seconds: 1,
        burst: 2,
    };
    let snapshot = snapshot(&[policy]);
    let pods = [
        pod(&url, &snapshot, true).await,
        pod(&url, &snapshot, true).await,
    ];
    let periods = 10_usize;
    let per_period = 30_usize;
    let interval = Duration::from_millis(1_000) / u32::try_from(per_period).unwrap();
    let mut admitted = vec![0_usize; periods];
    let started = tokio::time::Instant::now();

    // Three times the limit, alternating between the pods, on a fixed schedule.
    for step in 0..periods * per_period {
        tokio::time::sleep_until(started + interval * u32::try_from(step).unwrap()).await;
        let response = send(&pods[step % 2], request("/api/limited/1", Some(GOOD), None)).await;
        match response.status() {
            StatusCode::OK => admitted[step / per_period] += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected status {other}"),
        }
    }

    for (period, count) in admitted.iter().enumerate() {
        assert!(*count <= 12, "period {period} admitted {count}");
    }
    assert!(admitted.iter().sum::<usize>() >= 90, "{admitted:?}");
}
