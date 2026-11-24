//! The pipeline of the public listener (Story 10.2) in process: a real [`Pipeline`] over a snapshot
//! double, the production token repository with a verifier double, and a forwarder that records
//! what it receives.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_application::{FreshnessState, RequestAuthorizer};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CatalogueEntryState, CompiledRoleSet, ForwardError, FreshnessRule,
    GrantStatus, HttpMethod, PermissionGrant, PolicyVersion, PolicyView, RevocationView, RoleId,
    RouteState, ServiceName, SessionId, SubjectId, SubjectRef, TokenId, TokenMemo, TokenRejection,
    TokenRepository, UpstreamForwarder, UpstreamState, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings,
};
use rstest::rstest;
use service::bootstrap::gateway::pipeline::{
    Pipeline, TYPE_MALFORMED_PATH, UnauditedCommands, router,
};
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tower::ServiceExt as _;

const HOST: &str = "api.example.test";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const OTHER_USER: &str = "7a1c5e3b-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const NOW: u64 = 1_800_000_000;
const GOOD: &str = "good.token.value";
const OTHER: &str = "other.token.value";
const EXPIRED: &str = "expired.token.value";
const INVALID: &str = "invalid.token.value";
const REVOKED: &str = "revoked.token.value";
const HARD_BOUND: Duration = Duration::from_secs(15);

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
        .accepting(REVOKED, token(USER, "session-revoked"))
        .rejecting(EXPIRED, TokenRejection::Expired)
        .rejecting(INVALID, TokenRejection::Invalid)
}

fn entry(key: &str) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
    }
}

/// What the forwarder saw of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    upstream: String,
    uri: String,
    snapshot_handles: usize,
}

/// A forwarder that records the requests it receives, with the number of handles to the snapshot
/// at that moment, and answers 200, or panics.
#[derive(Debug)]
struct RecordingForwarder {
    view: Arc<CountingPolicyView>,
    seen: Mutex<Vec<Seen>>,
    panics: bool,
}

impl RecordingForwarder {
    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl UpstreamForwarder for RecordingForwarder {
    type Request = Request<Body>;
    type Response = Response;

    async fn forward(
        &self,
        target: UpstreamTarget,
        request: Request<Body>,
    ) -> Result<Response, ForwardError> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Seen {
                upstream: target.upstream().to_string(),
                uri: request.uri().to_string(),
                snapshot_handles: self.view.snapshot_handles(),
            });
        assert!(!self.panics, "a panic injected into the request task");
        Ok(StatusCode::OK.into_response())
    }
}

struct Gateway {
    router: Router,
    view: Arc<CountingPolicyView>,
    forwarder: Arc<RecordingForwarder>,
    clock: Arc<FakeBootClock>,
    freshness: Arc<FreshnessState>,
}

/// The snapshot of one service `users`: a route for `GET /api/users/{id}` and for
/// `GET /api/orders`, a catalogue with the first operation and, when `orders_elsewhere`, a service
/// `orders` that has the second. The user `USER` holds the key of `GET /api/users/{}`; the session
/// `session-revoked` is revoked.
fn snapshot(rng: &mut TestRng, orders_elsewhere: bool) -> GatewaySnapshot {
    let users = UpstreamState::of(upstream(rng, "users", "users").parts());
    let roles = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile([(
        PermissionGrant::parse("rest:users:GET /api/users/{}").unwrap(),
        GrantStatus::Active,
    )]);
    let users_route = route_draft(
        HOST,
        "/api/users/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    let orders_route = route_draft(HOST, "/api/orders", &[HttpMethod::Get], "users", users.id);
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(rng, &users_route).parts()))
        .with_route(RouteState::of(route(rng, &orders_route).parts()))
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![entry("rest:users:GET /api/users/{}")],
        )
        .with_assignments(
            SubjectRef::user(Uuid::parse(USER).unwrap()),
            vec![AssignmentState {
                role: roles,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(roles, granted)
        .with_revoked_session(SessionId::new("session-revoked").unwrap());
    if orders_elsewhere {
        snapshot = snapshot.with_catalogue(
            ServiceName::new("orders").unwrap(),
            vec![entry("rest:orders:GET /api/orders")],
        );
    }
    snapshot
}

fn gateway_over(view: CountingPolicyView, panics: bool) -> Gateway {
    let view = Arc::new(view);
    let boot = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let freshness = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD_BOUND, Duration::from_secs(2)),
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
        clock,
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    let forwarder = Arc::new(RecordingForwarder {
        view: Arc::clone(&view),
        seen: Mutex::default(),
        panics,
    });
    let pipeline = Pipeline::new(
        policy,
        Arc::clone(&freshness),
        tokens,
        Arc::new(authorizer),
        Arc::<RecordingForwarder>::clone(&forwarder),
    );
    Gateway {
        router: router(pipeline),
        view,
        forwarder,
        clock: boot,
        freshness,
    }
}

fn gateway() -> Gateway {
    let mut rng = TestRng::from_env();
    gateway_over(CountingPolicyView::serving(snapshot(&mut rng, true)), false)
}

fn request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::get(path).header("host", HOST);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::empty()).unwrap()
}

async fn send(gateway: &Gateway, request: Request<Body>) -> Response {
    gateway.router.clone().oneshot(request).await.unwrap()
}

async fn problem_type(response: Response) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    document["type"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_subject_holding_the_key_is_forwarded_with_the_canonical_path_after_one_snapshot_load() {
    let gateway = gateway();

    let response = send(&gateway, request("/api/users/%7Euser?x=1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        gateway.forwarder.seen(),
        [Seen {
            upstream: "users".to_owned(),
            uri: "/api/users/~user?x=1".to_owned(),
            snapshot_handles: 1,
        }]
    );
    assert_eq!(gateway.view.loads(), 1);
}

#[tokio::test]
async fn the_snapshot_is_loaded_once_per_request_and_released_before_the_forwarder_starts() {
    let gateway = gateway();

    for _ in 0..3 {
        assert_eq!(
            send(&gateway, request("/api/users/1", Some(GOOD)))
                .await
                .status(),
            StatusCode::OK
        );
    }

    assert_eq!(gateway.view.loads(), 3);
    assert!(
        gateway
            .forwarder
            .seen()
            .iter()
            .all(|seen| seen.snapshot_handles == 1)
    );
}

#[rstest]
#[case("/nothing")]
#[case("/api/users")]
#[tokio::test]
async fn a_request_matching_no_route_is_a_404_and_reaches_no_forwarder(#[case] path: &str) {
    let gateway = gateway();

    let response = send(&gateway, request(path, Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn another_host_or_method_matches_no_route() {
    let gateway = gateway();
    let other_host = Request::get("/api/users/1")
        .header("host", "other.example.test")
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .body(Body::empty())
        .unwrap();
    let trace = Request::builder()
        .method("TRACE")
        .uri("/api/users/1")
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();
    let post = Request::post("/api/users/1")
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();

    for request in [other_host, trace, post] {
        assert_eq!(
            send(&gateway, request).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(gateway.forwarder.seen(), []);
}

#[rstest]
#[case::double_encoded_dots("/api/users/%252e%252e")]
#[case::dot_dot_segment("/api/users/../x")]
#[case::encoded_slash("/api/users/a%2Fb")]
#[case::nul_byte("/api/users/a%00b")]
#[tokio::test]
async fn a_path_that_breaks_the_path_rule_is_a_400_and_reaches_no_forwarder(#[case] path: &str) {
    let gateway = gateway();

    let response = send(&gateway, request(path, Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(problem_type(response).await, TYPE_MALFORMED_PATH);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn a_path_of_more_than_2048_bytes_is_a_400() {
    let gateway = gateway();
    let long = format!("/api/users/{}", "a".repeat(2_048));

    let response = send(&gateway, request(&long, Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[rstest]
#[case::missing(None)]
#[case::invalid(Some(INVALID))]
#[case::expired(Some(EXPIRED))]
#[case::revoked(Some(REVOKED))]
#[case::unknown(Some("never.seen.token"))]
#[tokio::test]
async fn a_missing_invalid_expired_or_revoked_token_is_a_401_with_the_bearer_challenge(
    #[case] token: Option<&str>,
) {
    let gateway = gateway();

    let response = send(&gateway, request("/api/users/1", token)).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn a_valid_token_in_the_host_cookie_is_accepted() {
    let gateway = gateway();
    let request = Request::get("/api/users/1")
        .header("host", HOST)
        .header(COOKIE, format!("theme=dark; __Host-auth_token={GOOD}"))
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(gateway.forwarder.seen().len(), 1);
}

#[tokio::test]
async fn a_subject_without_the_key_of_the_route_gets_403_permission_missing() {
    let gateway = gateway();

    let response = send(&gateway, request("/api/users/1", Some(OTHER))).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(problem_type(response).await, "/problems/permission_missing");
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn the_refusal_of_an_operation_unknown_to_the_service_is_the_same_whether_or_not_another_service_has_it()
 {
    let mut rng = TestRng::from_env();
    let shared = gateway_over(CountingPolicyView::serving(snapshot(&mut rng, true)), false);
    let alone = gateway_over(
        CountingPolicyView::serving(snapshot(&mut rng, false)),
        false,
    );

    let with_other = send(&shared, request("/api/orders", Some(GOOD))).await;
    let without_other = send(&alone, request("/api/orders", Some(GOOD))).await;

    assert_eq!(with_other.status(), StatusCode::FORBIDDEN);
    assert_eq!(without_other.status(), StatusCode::FORBIDDEN);
    let first = problem_type(with_other).await;
    assert_eq!(first, "/problems/unknown_operation");
    assert_eq!(first, problem_type(without_other).await);
}

#[tokio::test]
async fn a_proof_older_than_the_hard_bound_is_a_503_iam_stale_and_never_an_allow() {
    let gateway = gateway();
    assert_eq!(
        send(&gateway, request("/api/users/1", Some(GOOD)))
            .await
            .status(),
        StatusCode::OK
    );

    gateway.clock.advance(HARD_BOUND + Duration::from_millis(1));
    let response = send(&gateway, request("/api/users/1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    assert_eq!(problem_type(response).await, "/problems/iam_stale");
    assert_eq!(gateway.forwarder.seen().len(), 1);
}

#[tokio::test]
async fn a_fenced_pod_is_a_503_iam_stale() {
    let gateway = gateway();
    gateway.freshness.invalidate();

    let response = send(&gateway, request("/api/users/1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn a_pod_without_a_snapshot_is_a_503_iam_stale() {
    let gateway = gateway_over(CountingPolicyView::empty(), false);

    let response = send(&gateway, request("/api/users/1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_type(response).await, "/problems/iam_stale");
    assert_eq!(gateway.view.loads(), 1);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn a_panic_in_the_request_task_is_a_500() {
    let mut rng = TestRng::from_env();
    let gateway = gateway_over(CountingPolicyView::serving(snapshot(&mut rng, true)), true);

    let response = send(&gateway, request("/api/users/1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn the_response_carries_the_request_id_of_the_request() {
    let gateway = gateway();
    let request = Request::get("/nothing")
        .header("host", HOST)
        .header("x-request-id", "req-42")
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(response.headers().get("x-request-id").unwrap(), "req-42");
}
