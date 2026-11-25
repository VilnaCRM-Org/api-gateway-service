//! The header rewrite of the pipeline (Story 10.4, FR-68) in process: a forwarder that records the
//! headers it receives stands for the echo upstream, over a snapshot with two upstreams, one that
//! takes the credentials of the caller and one that does not.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_application::FreshnessState;
use iam_domain::{
    AssignmentScope, AssignmentState, CompiledRoleSet, ForwardError, GrantStatus, HttpMethod,
    PermissionGrant, PolicyVersion, RoleId, RouteState, ServiceName, SubjectRef, UpstreamForwarder,
    UpstreamState, UpstreamTarget,
};
use rstest::rstest;
use service::bootstrap::gateway::pipeline::ClientAddress;
use shared_domain::Uuid;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream_forwarding;
use tower::ServiceExt as _;

use super::{GOOD, HOST, OTHER, ROLE, USER, entry, pipeline_over};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
const COOKIES: &str = "theme=dark;__Host-auth_token=good.token.value ;  other=1";

/// What the echo upstream received: the upstream that took the request and its headers.
#[derive(Debug)]
struct Echo {
    upstream: String,
    headers: HeaderMap,
}

/// A forwarder that records the headers of each request and answers 200.
#[derive(Debug, Default)]
struct EchoForwarder {
    seen: Mutex<Vec<Echo>>,
}

#[async_trait::async_trait]
impl UpstreamForwarder for EchoForwarder {
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
            .push(Echo {
                upstream: target.upstream().to_string(),
                headers: request.headers().clone(),
            });
        let mut response = StatusCode::OK.into_response();
        response
            .headers_mut()
            .insert("x-iam-policy-version", "upstream-forged".parse().unwrap());
        Ok(response)
    }
}

struct Echoing {
    router: axum::Router,
    forwarder: Arc<EchoForwarder>,
    freshness: Arc<FreshnessState>,
}

impl Echoing {
    fn received(&self) -> Vec<Echo> {
        std::mem::take(
            &mut *self
                .forwarder
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    async fn send(&self, request: Request<Body>) -> Response {
        self.router.clone().oneshot(request).await.unwrap()
    }
}

/// A snapshot at version 7 with the upstream `users`, which keeps the credentials to itself, and
/// the upstream `control`, which takes them. The user `USER` may call both routes.
fn snapshot(rng: &mut TestRng) -> GatewaySnapshot {
    let users = UpstreamState::of(upstream_forwarding(rng, "users", "users", false).parts());
    let control = UpstreamState::of(upstream_forwarding(rng, "control", "control", true).parts());
    let role = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile([
        (
            PermissionGrant::parse("rest:users:GET /api/users/{}").unwrap(),
            GrantStatus::Active,
        ),
        (
            PermissionGrant::parse("rest:control:GET /api/control").unwrap(),
            GrantStatus::Active,
        ),
    ]);
    let users_route = route_draft(
        HOST,
        "/api/users/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    let control_route = route_draft(
        HOST,
        "/api/control",
        &[HttpMethod::Get],
        "control",
        control.id,
    );
    GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_upstream(control)
        .with_route(RouteState::of(route(rng, &users_route).parts()))
        .with_route(RouteState::of(route(rng, &control_route).parts()))
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![entry("rest:users:GET /api/users/{}")],
        )
        .with_catalogue(
            ServiceName::new("control").unwrap(),
            vec![entry("rest:control:GET /api/control")],
        )
        .with_assignments(
            SubjectRef::user(Uuid::parse(USER).unwrap()),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, granted)
}

fn echoing() -> Echoing {
    let mut rng = TestRng::from_env();
    let view = Arc::new(CountingPolicyView::serving(snapshot(&mut rng)));
    let forwarder = Arc::new(EchoForwarder::default());
    let (router, _clock, freshness) =
        pipeline_over(&view, Arc::<EchoForwarder>::clone(&forwarder), None);
    Echoing {
        router,
        forwarder,
        freshness,
    }
}

fn from_client(mut request: Request<Body>) -> Request<Body> {
    request
        .extensions_mut()
        .insert(ClientAddress::from(SocketAddr::new(CLIENT, 51_000)));
    request
}

fn authorized(path: &str, token: &str) -> Request<Body> {
    from_client(
        Request::get(path)
            .header("host", HOST)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
}

fn text<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn forged_principal_and_forwarding_headers_never_reach_the_upstream() {
    let gateway = echoing();
    let forged = from_client(
        Request::get("/api/users/1")
            .header("host", HOST)
            .header(AUTHORIZATION, format!("Bearer {GOOD}"))
            .header("x-iam-subject", "forged-subject")
            .header("x-iam-policy-version", "999")
            .header("x-iam-session", "forged-session")
            .header("x-iam-subject-kind", "service")
            .header("forwarded", "for=6.6.6.6")
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-forwarded-host", "evil.test")
            .body(Body::empty())
            .unwrap(),
    );

    let response = gateway.send(forged).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = gateway.received();
    let headers = &received.first().unwrap().headers;
    assert_eq!(text(headers, "x-iam-subject"), Some(USER));
    assert_eq!(text(headers, "x-iam-subject-kind"), Some("user"));
    assert_eq!(text(headers, "x-iam-session"), Some("session-1"));
    assert_eq!(text(headers, "x-iam-policy-version"), Some("7"));
    assert_eq!(headers.get("forwarded"), None);
    assert_eq!(headers.get("x-forwarded-host"), None);
    assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
    assert_eq!(text(headers, "x-forwarded-for"), Some("203.0.113.9"));
}

#[tokio::test]
async fn an_authorized_request_carries_the_decision_the_request_id_and_the_client_address() {
    let gateway = echoing();

    let response = gateway.send(authorized("/api/users/1", GOOD)).await;

    let request_id = text(response.headers(), "x-request-id").unwrap().to_owned();
    let received = gateway.received();
    let headers = &received.first().unwrap().headers;
    assert_eq!(received.first().unwrap().upstream, "users");
    assert_eq!(text(headers, "x-iam-subject"), Some(USER));
    assert_eq!(text(headers, "x-iam-subject-kind"), Some("user"));
    assert_eq!(text(headers, "x-iam-session"), Some("session-1"));
    assert_eq!(text(headers, "x-iam-policy-version"), Some("7"));
    assert_eq!(text(headers, "x-request-id"), Some(request_id.as_str()));
    assert_eq!(text(headers, "x-forwarded-for"), Some("203.0.113.9"));
}

#[rstest]
#[case("/api/control", "control")]
#[case("/api/users/1", "users")]
#[tokio::test]
async fn credentials_go_unchanged_only_to_an_upstream_that_forwards_them(
    #[case] path: &str,
    #[case] upstream: &str,
) {
    let gateway = echoing();
    let request = from_client(
        Request::get(path)
            .header("host", HOST)
            .header(AUTHORIZATION, format!("Bearer {GOOD}"))
            .header(COOKIE, COOKIES)
            .body(Body::empty())
            .unwrap(),
    );

    let response = gateway.send(request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = gateway.received();
    let echo = received.first().unwrap();
    assert_eq!(echo.upstream, upstream);
    if upstream == "control" {
        assert_eq!(
            text(&echo.headers, "authorization"),
            Some(format!("Bearer {GOOD}").as_str())
        );
        assert_eq!(text(&echo.headers, "cookie"), Some(COOKIES));
    } else {
        assert_eq!(echo.headers.get("authorization"), None);
        assert_eq!(text(&echo.headers, "cookie"), Some("theme=dark; other=1"));
    }
}

#[tokio::test]
async fn a_cookie_session_reaches_an_upstream_that_forwards_credentials_only_as_the_cookie() {
    let gateway = echoing();
    let request = from_client(
        Request::get("/api/control")
            .header("host", HOST)
            .header(COOKIE, format!("__Host-auth_token={GOOD}; other=1"))
            .body(Body::empty())
            .unwrap(),
    );

    let response = gateway.send(request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = gateway.received();
    let headers = &received.first().unwrap().headers;
    assert_eq!(text(headers, "x-iam-subject"), Some(USER));
    assert_eq!(headers.get("authorization"), None);
    assert_eq!(
        text(headers, "cookie"),
        Some(format!("__Host-auth_token={GOOD}; other=1").as_str())
    );
}

#[rstest]
#[case::forwarded_by_the_upstream(authorized("/api/users/1", GOOD), StatusCode::OK)]
#[case::unauthorized(
    from_client(Request::get("/api/users/1").header("host", HOST).body(Body::empty()).unwrap()),
    StatusCode::UNAUTHORIZED
)]
#[case::forbidden(authorized("/api/users/1", OTHER), StatusCode::FORBIDDEN)]
#[case::not_found(authorized("/nothing", GOOD), StatusCode::NOT_FOUND)]
#[tokio::test]
async fn every_response_names_the_policy_version_of_the_snapshot(
    #[case] request: Request<Body>,
    #[case] status: StatusCode,
) {
    let gateway = echoing();

    let response = gateway.send(request).await;

    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get_all("x-iam-policy-version")
            .iter()
            .count(),
        1
    );
    assert_eq!(text(response.headers(), "x-iam-policy-version"), Some("7"));
}

#[tokio::test]
async fn the_503_of_a_pod_that_is_not_fresh_names_the_published_version() {
    let gateway = echoing();
    gateway.freshness.invalidate();

    let response = gateway.send(authorized("/api/users/1", GOOD)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(text(response.headers(), "x-iam-policy-version"), Some("7"));
    assert!(gateway.received().is_empty());
}
