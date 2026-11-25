//! The rate-limit step of the pipeline against the compose Valkey (Story 12.2, FR-65): two gateways
//! in one process share one Valkey, so a quota holds across the fleet.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_application::{FreshnessState, RateLimitGate, RequestAuthorizer};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock, BootInstant, CatalogueEntryState, CompiledRoleSet, ForwardError, FreshnessRule,
    GrantStatus, HttpMethod, LocalRateLimiter, PermissionGrant, PolicyVersion, PolicyView,
    RateDecisionRule, RateKey, RateKeyKind, RateKeyParts, RateLimitStore, RatePolicyId,
    RequestDigester, RevocationView, RoleId, RouteState, ServiceName, SessionId, SubjectId,
    SubjectRef, TokenId, TokenMemo, TokenRejection, TokenRepository, UpstreamForwarder,
    UpstreamState, UpstreamTarget,
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
use test_support::rate_policy::rate_policy_state;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::io::copy_bidirectional;
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
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
    }
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
        snapshot.with_rate_policy(rate_policy_state(
            policy.id,
            policy.kind,
            policy.limit,
            policy.period_seconds,
            policy.burst,
        ))
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

/// One gateway pod: its own pipeline, store connection and local limiter over the Valkey at `url`.
async fn pod(url: &str, snapshot: &GatewaySnapshot, warm: bool) -> Router {
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
    let boot_clock: Arc<dyn BootClock> = Arc::new(LinuxBootClock);
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
    let gate = RateLimitGate::new(store, local, digester, boot_clock, STORE_TIMEOUT);
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
