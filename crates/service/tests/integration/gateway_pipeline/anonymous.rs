//! Routes flagged `anonymous` (Story 10.6, FR-63) through the pipeline with the production
//! `HyperUpstreamForwarder` and a fake upstream on a loopback socket: a request with no token or
//! with an invalid one is forwarded without a principal header, the freshness fence and the body
//! limit still apply, and a route that a newer version makes protected asks for a token again.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request as UpstreamRequest, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_domain::{HttpMethod, PolicyVersion, RouteFlag, RouteFlags, RouteState, UpstreamState};
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream_forwarding;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use super::proxy::proxy_over;
use super::{HARD_BOUND, HOST, INVALID};

/// The body limit of the anonymous route of the fixtures, in bytes.
const LIMIT: i64 = 16;

/// What the fake upstream saw of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    authorization: Option<String>,
    subject: Option<String>,
    policy_version: Option<String>,
}

/// The requests that reached the fake upstream.
#[derive(Debug, Clone, Default)]
struct Upstream(Arc<Mutex<Vec<Received>>>);

impl Upstream {
    fn received(&self) -> Vec<Received> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn header(request: &UpstreamRequest, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn record(State(seen): State<Upstream>, request: UpstreamRequest) -> Response {
    seen.0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Received {
            authorization: header(&request, "authorization"),
            subject: header(&request, "x-iam-subject"),
            policy_version: header(&request, "x-iam-policy-version"),
        });
    StatusCode::OK.into_response()
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake upstream on a free loopback port"
)]
async fn serve(seen: Upstream) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new().fallback(record).with_state(seen);
    drop(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    address
}

/// The snapshot of one upstream `users`, which forwards credentials, and the route
/// `POST /api/signin` of the service `users` that is `anonymous` or protected, with a body limit
/// of [`LIMIT`] bytes. Neither the service nor any subject holds a key.
fn state(anonymous: bool) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let users = UpstreamState::of(upstream_forwarding(&mut rng, "users", "users", true).parts());
    let mut draft = route_draft(HOST, "/api/signin", &[HttpMethod::Post], "users", users.id);
    draft.flags = RouteFlags::default().with(RouteFlag::Anonymous, anonymous);
    draft.body_limit = LIMIT;
    GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(&mut rng, &draft).parts()))
}

fn signin(token: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::post("/api/signin")
        .header("host", HOST)
        .header("x-iam-subject", "forged-subject")
        .header("x-iam-policy-version", "99");
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

async fn problem_type(response: Response) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    document["type"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_request_without_a_token_and_one_with_an_invalid_token_are_forwarded_without_a_subject() {
    let seen = Upstream::default();
    let (router, _clock) = proxy_over(serve(seen.clone()).await, state(true));

    let without = router.clone().oneshot(signin(None, "{}")).await.unwrap();
    let invalid = router.oneshot(signin(Some(INVALID), "{}")).await.unwrap();

    assert_eq!(without.status(), StatusCode::OK);
    assert_eq!(invalid.status(), StatusCode::OK);
    assert_eq!(
        seen.received(),
        [
            Received {
                authorization: None,
                subject: None,
                policy_version: None,
            },
            Received {
                authorization: Some(format!("Bearer {INVALID}")),
                subject: None,
                policy_version: None,
            },
        ]
    );
}

#[tokio::test]
async fn a_proof_older_than_the_hard_bound_is_a_503_iam_stale_on_an_anonymous_route() {
    let seen = Upstream::default();
    let (router, clock) = proxy_over(serve(seen.clone()).await, state(true));
    clock.advance(HARD_BOUND + Duration::from_millis(1));

    let response = router.oneshot(signin(None, "{}")).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_type(response).await, "/problems/iam_stale");
    assert_eq!(seen.received(), []);
}

#[tokio::test]
async fn a_body_above_the_limit_of_an_anonymous_route_is_a_413_and_the_upstream_sees_nothing() {
    let seen = Upstream::default();
    let (router, _clock) = proxy_over(serve(seen.clone()).await, state(true));
    let above = "x".repeat(usize::try_from(LIMIT).unwrap() + 1);

    let response = router.oneshot(signin(None, &above)).await.unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(seen.received(), []);
}

#[tokio::test]
async fn a_route_that_a_new_version_makes_protected_answers_401_without_a_token() {
    let seen = Upstream::default();
    let address = serve(seen.clone()).await;
    let (anonymous, _clock) = proxy_over(address, state(true));
    let (protected, _clock) = proxy_over(address, state(false));

    let before = anonymous.oneshot(signin(None, "{}")).await.unwrap();
    let after = protected.oneshot(signin(None, "{}")).await.unwrap();

    assert_eq!(before.status(), StatusCode::OK);
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(seen.received().len(), 1);
}
