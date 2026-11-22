use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use http_body_util::BodyExt as _;
use iam_application::{Principal, ResolveTokenQueryHandler};
use iam_domain::{
    AccessToken, AccessTokenParts, CallerTokenRule, ServiceName, SessionId, SubjectId, TokenId,
    TokenIdentity, TokenRejection, TokenRepository,
};
use rstest::rstest;
use serde_json::Value;
use shared_domain::{QueryBus, Uuid};
use shared_infrastructure::bus::InMemoryQueryBus;
use test_support::log::LogRecorder;
use test_support::token::FakeTokenRepository;
use tower::ServiceExt as _;

use super::{AUTH_COOKIE, Authenticator, require_principal, resolve_principal};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const USER_TOKEN: &str = "user.token.signature";
const SERVICE_TOKEN: &str = "service.token.signature";
const STRAY_SERVICE_TOKEN: &str = "stray-service.token.signature";
const REVOKED_TOKEN: &str = "revoked.token.signature";
const UNAVAILABLE_TOKEN: &str = "unavailable.token.signature";
const CALLER_AUDIENCE: &str = "vilnacrm-iam";

fn identity(subject: SubjectId, audiences: &[&str]) -> TokenIdentity {
    let session = match subject {
        SubjectId::User(_) => Some(SessionId::new("session-1").unwrap()),
        SubjectId::Service(_) => None,
    };
    TokenIdentity::from(
        &AccessToken::new(AccessTokenParts {
            subject,
            session,
            token_id: TokenId::new("jti-1").unwrap(),
            roles: Vec::new(),
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(600))
                .unwrap(),
        })
        .with_audiences(
            audiences
                .iter()
                .map(|&audience| audience.to_owned())
                .collect(),
        ),
    )
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse(USER).unwrap())
}

fn service() -> SubjectId {
    SubjectId::Service(ServiceName::new("billing").unwrap())
}

fn tokens() -> FakeTokenRepository {
    FakeTokenRepository::new()
        .accepting(USER_TOKEN, identity(user(), &["vilnacrm-api"]))
        .accepting(
            SERVICE_TOKEN,
            identity(service(), &["vilnacrm-api", CALLER_AUDIENCE]),
        )
        .accepting(STRAY_SERVICE_TOKEN, identity(service(), &["vilnacrm-api"]))
        .rejecting(REVOKED_TOKEN, TokenRejection::Revoked)
        .rejecting(UNAVAILABLE_TOKEN, TokenRejection::Unavailable)
}

async fn caller(principal: Option<Extension<Principal>>) -> String {
    principal.map_or_else(
        || "anonymous".to_owned(),
        |Extension(principal)| principal.subject().to_string(),
    )
}

/// A router with a route behind each middleware, and the token repository it asks.
fn app() -> (Router, Arc<FakeTokenRepository>) {
    let tokens = Arc::new(tokens());
    let rule = CallerTokenRule::new(CALLER_AUDIENCE.to_owned(), Duration::from_secs(600));
    let shared: Arc<dyn TokenRepository> = Arc::<FakeTokenRepository>::clone(&tokens);
    let handler = ResolveTokenQueryHandler::new(shared, rule);
    let bus: Arc<dyn QueryBus> = Arc::new(InMemoryQueryBus::new().register(handler).unwrap());
    let authenticator = Authenticator::new(bus);
    let router = Router::new()
        .route(
            "/protected",
            get(caller).layer(from_fn_with_state(authenticator.clone(), require_principal)),
        )
        .route(
            "/optional",
            get(caller).layer(from_fn_with_state(authenticator, resolve_principal)),
        );
    (router, tokens)
}

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    content_type: Option<String>,
    body: String,
}

async fn send(path: &str, headers: &[(&str, &str)]) -> (Answer, Arc<FakeTokenRepository>) {
    let (router, tokens) = app();
    let mut builder = Request::builder().uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (challenge, content_type) = {
        let header = |name| {
            response
                .headers()
                .get(name)
                .map(|value: &axum::http::HeaderValue| value.to_str().unwrap().to_owned())
        };
        (header(WWW_AUTHENTICATE), header(CONTENT_TYPE))
    };
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let answer = Answer {
        status,
        challenge,
        content_type,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    };
    (answer, tokens)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn assert_unauthenticated(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.challenge.as_deref(), Some("Bearer"));
    assert_eq!(
        answer.content_type.as_deref(),
        Some("application/problem+json")
    );
    let problem: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(problem["status"], 401);
    assert_eq!(problem["title"], "Unauthorized");
    assert_eq!(problem["detail"], "A valid bearer token is required.");
}

#[tokio::test]
async fn a_request_without_a_token_is_the_401_problem_with_the_bearer_challenge() {
    let (answer, _tokens) = send("/protected", &[]).await;

    assert_unauthenticated(&answer);
}

#[rstest]
#[case::user(USER_TOKEN, USER)]
#[case::service_with_the_caller_audience(SERVICE_TOKEN, "billing")]
#[tokio::test]
async fn a_valid_bearer_token_passes_with_its_principal(#[case] token: &str, #[case] who: &str) {
    let (answer, _tokens) = send("/protected", &[("authorization", bearer(token).as_str())]).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, who);
}

#[rstest]
#[case::lower_case("bearer")]
#[case::upper_case("BEARER")]
#[tokio::test]
async fn the_scheme_is_case_insensitive(#[case] scheme: &str) {
    let value = format!("{scheme} {USER_TOKEN}");

    let (answer, _tokens) = send("/protected", &[("authorization", value.as_str())]).await;

    assert_eq!(answer.body, USER);
}

#[rstest]
#[case::malformed("Bearer not-a-token")]
#[case::revoked(&bearer(REVOKED_TOKEN))]
#[case::service_without_the_caller_audience(&bearer(STRAY_SERVICE_TOKEN))]
#[case::blank("Bearer ")]
#[case::another_scheme(&format!("Basic {USER_TOKEN}"))]
#[case::no_scheme(USER_TOKEN)]
#[tokio::test]
async fn every_refused_token_is_the_same_401_problem(#[case] authorization: &str) {
    let (answer, _tokens) = send("/protected", &[("authorization", authorization)]).await;

    assert_unauthenticated(&answer);
}

#[tokio::test]
async fn an_authorization_value_that_is_not_text_is_the_401_problem() {
    let (router, _tokens) = app();
    let request = Request::builder()
        .uri("/protected")
        .header(
            AUTHORIZATION,
            axum::http::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        )
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unreadable_revocation_state_is_the_500_problem_without_a_challenge() {
    let (answer, _tokens) = send(
        "/protected",
        &[("authorization", bearer(UNAVAILABLE_TOKEN).as_str())],
    )
    .await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(answer.challenge, None);
}

#[rstest]
#[case::alone(format!("{AUTH_COOKIE}={USER_TOKEN}"))]
#[case::among_others(format!("theme=dark; {AUTH_COOKIE}={USER_TOKEN}; lang=uk"))]
#[case::without_a_value_before_it(format!("flag; {AUTH_COOKIE}={USER_TOKEN}"))]
#[tokio::test]
async fn a_valid_token_in_the_cookie_authenticates_like_a_bearer_token(#[case] cookie: String) {
    let (answer, _tokens) = send("/protected", &[("cookie", cookie.as_str())]).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, USER);
}

#[tokio::test]
async fn the_cookie_is_found_in_any_cookie_header() {
    let auth = format!("{AUTH_COOKIE}={USER_TOKEN}");

    let (answer, _tokens) = send(
        "/protected",
        &[("cookie", "theme=dark"), ("cookie", auth.as_str())],
    )
    .await;

    assert_eq!(answer.body, USER);
}

#[rstest]
#[case::invalid(format!("{AUTH_COOKIE}=not-a-token"))]
#[case::revoked(format!("{AUTH_COOKIE}={REVOKED_TOKEN}"))]
#[case::another_cookie(format!("auth_token={USER_TOKEN}"))]
#[tokio::test]
async fn an_invalid_cookie_token_is_the_same_401_problem(#[case] cookie: String) {
    let (answer, _tokens) = send("/protected", &[("cookie", cookie.as_str())]).await;

    assert_unauthenticated(&answer);
}

#[tokio::test]
async fn the_authorization_header_wins_over_the_cookie() {
    let cookie = format!("{AUTH_COOKIE}={USER_TOKEN}");

    let (answer, _tokens) = send(
        "/protected",
        &[
            ("authorization", "Basic abc"),
            (COOKIE.as_str(), cookie.as_str()),
        ],
    )
    .await;

    assert_unauthenticated(&answer);
}

#[tokio::test]
async fn the_optional_route_resolves_a_valid_token() {
    let (answer, _tokens) = send(
        "/optional",
        &[("authorization", bearer(USER_TOKEN).as_str())],
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, USER);
}

#[rstest]
#[case::invalid(&bearer("not-a-token"))]
#[case::unavailable(&bearer(UNAVAILABLE_TOKEN))]
#[tokio::test]
async fn the_optional_route_lets_a_refused_token_through_without_a_principal(
    #[case] authorization: &str,
) {
    let (answer, tokens) = send("/optional", &[("authorization", authorization)]).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, "anonymous");
    assert_eq!(tokens.calls(), 1);
}

#[tokio::test]
async fn the_optional_route_does_not_resolve_a_request_without_a_token() {
    let (answer, tokens) = send("/optional", &[]).await;

    assert_eq!(answer.body, "anonymous");
    assert_eq!(tokens.calls(), 0);
}

#[tokio::test]
async fn the_authorization_value_never_reaches_a_log_line() {
    let (recorder, _guard) = LogRecorder::install();

    for token in [USER_TOKEN, REVOKED_TOKEN, UNAVAILABLE_TOKEN, "not-a-token"] {
        let _answer = send("/protected", &[("authorization", bearer(token).as_str())]).await;
        let _answer = send("/optional", &[("authorization", bearer(token).as_str())]).await;
    }

    for line in recorder.lines() {
        let printed = format!("{line:?}");
        for token in [USER_TOKEN, REVOKED_TOKEN, UNAVAILABLE_TOKEN, "not-a-token"] {
            assert!(!printed.contains(token), "{printed}");
        }
    }
}
