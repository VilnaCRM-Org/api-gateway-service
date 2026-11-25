//! CORS preflights and the CSRF rule (Story 10.12, FR-89) through the pipeline: a preflight is
//! answered before authentication and never reaches the forwarder, allowed origins get the exact
//! `Access-Control-Allow-Origin` and `Vary: Origin`, and a cookie-authenticated unsafe request or
//! WebSocket upgrade from another site is refused 403 `csrf_rejected`.

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE, ORIGIN, REFERER, VARY};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use iam_domain::{
    AssignmentScope, AssignmentState, CompiledRoleSet, CorsDraft, GrantStatus, HttpMethod,
    PermissionGrant, PolicyVersion, RoleId, RouteState, ServiceName, SubjectRef, UpstreamState,
};
use rstest::rstest;
use shared_domain::Uuid;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;

use super::{GOOD, Gateway, HOST, ROLE, USER, entry, gateway_over, problem_type, send};

const CRM: &str = "https://crm.example.test";
const EVIL: &str = "https://evil.example.test";
const OWN: &str = "https://api.example.test";
const COOKIE_AUTH: &str = "__Host-auth_token=good.token.value; theme=dark";

/// A snapshot with `GET /api/users/{id}` and `POST` and `DELETE` on `/api/users` (the policy lists
/// `DELETE` on neither), all with a CORS policy that
/// allows [`CRM`] with credentials, and `GET /api/plain` without one. `USER` holds the keys of the
/// first two.
fn snapshot() -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let users = UpstreamState::of(upstream(&mut rng, "users", "users").parts());
    let policy = CorsDraft {
        origins: vec![CRM.to_owned()],
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        headers: vec!["Content-Type".to_owned()],
        allow_credentials: true,
        max_age_seconds: 600,
    };
    let mut read = route_draft(
        HOST,
        "/api/users/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    read.cors = Some(policy.clone());
    let mut write = route_draft(
        HOST,
        "/api/users",
        &[HttpMethod::Post, HttpMethod::Delete],
        "users",
        users.id,
    );
    write.cors = Some(policy);
    let plain = route_draft(HOST, "/api/plain", &[HttpMethod::Get], "users", users.id);
    let role = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile([
        (
            PermissionGrant::parse("rest:users:GET /api/users/{}").unwrap(),
            GrantStatus::Active,
        ),
        (
            PermissionGrant::parse("rest:users:POST /api/users").unwrap(),
            GrantStatus::Active,
        ),
        (
            PermissionGrant::parse("rest:users:GET /api/plain").unwrap(),
            GrantStatus::Active,
        ),
    ]);
    GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(&mut rng, &read).parts()))
        .with_route(RouteState::of(route(&mut rng, &write).parts()))
        .with_route(RouteState::of(route(&mut rng, &plain).parts()))
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![
                entry("rest:users:GET /api/users/{}"),
                entry("rest:users:POST /api/users"),
                entry("rest:users:GET /api/plain"),
            ],
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

fn gateway() -> Gateway {
    gateway_over(CountingPolicyView::serving(snapshot()), false)
}

fn preflight(path: &str, origin: &str, method: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri(path)
        .header("host", HOST)
        .header(ORIGIN, origin)
        .header("access-control-request-method", method)
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap()
}

fn header<'response>(response: &'response Response, name: &str) -> Option<&'response str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn cookie_post(origin: Option<&str>, referer: Option<&str>) -> Request<Body> {
    let mut builder = Request::post("/api/users")
        .header("host", HOST)
        .header(COOKIE, COOKIE_AUTH);
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    if let Some(referer) = referer {
        builder = builder.header(REFERER, referer);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn an_allowed_preflight_is_answered_without_a_token_and_never_reaches_the_upstream() {
    let gateway = gateway();

    let response = send(&gateway, preflight("/api/users", CRM, "POST")).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(header(&response, "access-control-allow-origin"), Some(CRM));
    assert_eq!(
        header(&response, "access-control-allow-methods"),
        Some("GET, POST")
    );
    assert_eq!(
        header(&response, "access-control-allow-headers"),
        Some("Content-Type")
    );
    assert_eq!(
        header(&response, "access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(header(&response, "access-control-max-age"), Some("600"));
    assert_eq!(gateway.forwarder.seen(), []);
}

#[rstest]
#[case::foreign_origin("/api/users", EVIL, "POST")]
#[case::method_outside_the_policy("/api/users", CRM, "DELETE")]
#[case::route_without_a_policy("/api/plain", CRM, "GET")]
#[case::method_the_gateway_does_not_know("/api/users", CRM, "BREW")]
#[tokio::test]
async fn a_preflight_the_policy_does_not_allow_is_403_cors_rejected(
    #[case] path: &str,
    #[case] origin: &str,
    #[case] method: &str,
) {
    let gateway = gateway();

    let response = send(&gateway, preflight(path, origin, method)).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(header(&response, "access-control-allow-origin"), None);
    assert_eq!(problem_type(response).await, "/problems/cors_rejected");
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn a_preflight_for_a_path_without_a_route_is_a_404() {
    let gateway = gateway();

    let response = send(&gateway, preflight("/nothing", CRM, "GET")).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(gateway.forwarder.seen(), []);
}

#[tokio::test]
async fn an_allowed_cross_origin_get_carries_the_exact_origin_and_vary_origin() {
    let gateway = gateway();
    let request = Request::get("/api/users/1")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(ORIGIN, CRM)
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "access-control-allow-origin"), Some(CRM));
    assert_eq!(
        header(&response, "access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(header(&response, VARY.as_str()), Some("Origin"));
    assert_eq!(gateway.forwarder.seen().len(), 1);
}

#[tokio::test]
async fn a_foreign_origin_on_a_get_gets_no_cors_headers() {
    let gateway = gateway();
    let request = Request::get("/api/users/1")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(ORIGIN, EVIL)
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(header(&response, "access-control-allow-origin"), None);
    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

#[rstest]
#[case::own_origin(Some(OWN), None, StatusCode::OK)]
#[case::allowed_origin(Some(CRM), None, StatusCode::OK)]
#[case::foreign_origin(Some(EVIL), None, StatusCode::FORBIDDEN)]
#[case::own_referer(None, Some("https://api.example.test/app"), StatusCode::OK)]
#[case::neither(None, None, StatusCode::FORBIDDEN)]
#[tokio::test]
async fn a_cookie_authenticated_post_needs_an_own_or_allowed_origin(
    #[case] origin: Option<&str>,
    #[case] referer: Option<&str>,
    #[case] status: StatusCode,
) {
    let gateway = gateway();

    let response = send(&gateway, cookie_post(origin, referer)).await;

    assert_eq!(response.status(), status);
    if status == StatusCode::FORBIDDEN {
        assert_eq!(problem_type(response).await, "/problems/csrf_rejected");
        assert_eq!(gateway.forwarder.seen(), []);
    } else {
        assert_eq!(gateway.forwarder.seen().len(), 1);
    }
}

#[tokio::test]
async fn a_bearer_authenticated_post_from_a_foreign_origin_is_authorized_as_usual() {
    let gateway = gateway();
    let request = Request::post("/api/users")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(ORIGIN, EVIL)
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(gateway.forwarder.seen().len(), 1);
}

#[tokio::test]
async fn a_cookie_authenticated_websocket_upgrade_from_a_foreign_origin_is_refused_before_any_upgrade()
 {
    let gateway = gateway();
    let upgrade = |origin: &str| {
        Request::get("/api/users/1")
            .header("host", HOST)
            .header(COOKIE, COOKIE_AUTH)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header(ORIGIN, origin)
            .body(Body::empty())
            .unwrap()
    };

    let refused = send(&gateway, upgrade(EVIL)).await;

    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(problem_type(refused).await, "/problems/csrf_rejected");
    assert_eq!(gateway.forwarder.seen(), []);
    assert_eq!(send(&gateway, upgrade(CRM)).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_cookie_authenticated_get_is_not_checked() {
    let gateway = gateway();
    let request = Request::get("/api/users/1")
        .header("host", HOST)
        .header(COOKIE, COOKIE_AUTH)
        .header(ORIGIN, EVIL)
        .body(Body::empty())
        .unwrap();

    assert_eq!(send(&gateway, request).await.status(), StatusCode::OK);
}
