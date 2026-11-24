//! Authentication of IAM's callers through the production wiring: tokens signed at test time with
//! an ephemeral RSA key, verified by `JwtAccessTokenVerifier` and checked for revocation in
//! PostgreSQL, sent to a test-local protected route on the IAM router layer.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use clap::Parser as _;
use http_body_util::BodyExt as _;
use iam_application::Principal;
use iam_domain::{
    AccessTokenVerifier, ActorRef, CallerTokenRule, RevocationRepository as _, RevocationSource,
    SessionId, SessionRevocation, SessionRevocationId, TokenLifetimeRule,
};
use iam_infrastructure::{JwtAccessTokenVerifier, JwtSettings, PgRevocationRepository};
use serde_json::{Value, json};
use service::bootstrap::{Adapters, router_with_iam_routes, token_repository};
use service::cli::{Cli, Command};
use service::config::Config;
use service::http::AppState;
use service::http::authentication::AUTH_COOKIE;
use shared_domain::{Clock, Uuid};
use sqlx::PgPool;
use test_support::clock::FixedClock;
use tower::ServiceExt as _;

use crate::support::database_url;

#[path = "../../../authorization/iam/infrastructure/src/token/test_keys.rs"]
pub(crate) mod test_keys;

use test_keys::{
    AUDIENCE, ISSUER, NOW, TestKey, USER_ID, key_file, scratch_dir, service_claims, unsigned,
    user_claims,
};

const PROTECTED: &str = "/api/test-protected";
const CALLER_AUDIENCE: &str = "vilnacrm-iam";
const REVOKED_SESSION: &str = "session-revoked";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn with(mut claims: Value, name: &str, value: Value) -> Value {
    claims[name] = value;
    claims
}

/// The configuration of the binary with the token settings of the test keys: 15-minute tokens,
/// 30 seconds of skew and service callers limited to 10 minutes with the IAM audience.
pub(crate) fn config(name: &str, key: &TestKey) -> Config {
    let Command::Serve(args) = Cli::parse_from(["service", "serve"]).command else {
        panic!("`serve` arguments expected");
    };
    let mut config = Config::from_args(args).unwrap();
    let path = scratch_dir(name).join("keys.pem");
    std::fs::write(&path, key_file(&[key])).unwrap();
    config.tokens.public_keys_file = path;
    config.tokens.jwt = JwtSettings {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        lifetime: TokenLifetimeRule::new(Duration::from_mins(15), Duration::from_secs(30)),
    };
    config.tokens.callers =
        CallerTokenRule::new(CALLER_AUDIENCE.to_owned(), Duration::from_mins(10));
    config
}

async fn caller(Extension(principal): Extension<Principal>) -> String {
    principal.subject().to_string()
}

/// The production wiring over the test database, its verifier on a clock fixed at [`NOW`], with
/// the protected route on the IAM router.
async fn app(pool: &PgPool, name: &str, key: &TestKey) -> Router {
    let mut config = config(name, key);
    config.database.url = database_url(pool).await;
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(
        JwtAccessTokenVerifier::from_file(
            &config.tokens.public_keys_file,
            &config.tokens.jwt,
            Arc::clone(&clock),
        )
        .unwrap(),
    );
    let mut adapters = Adapters::connect(&config).await.unwrap();
    adapters.tokens = token_repository(&config, verifier, &clock, pool);
    let routes: Router<AppState> = Router::new().route(PROTECTED, get(caller));
    router_with_iam_routes(adapters, &config, routes).unwrap()
}

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    content_type: Option<String>,
    body: String,
}

async fn send(app: &Router, header: Option<(header::HeaderName, String)>) -> Answer {
    let mut builder = Request::get(PROTECTED);
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (challenge, content_type) = {
        let text = |name: header::HeaderName| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        (text(header::WWW_AUTHENTICATE), text(header::CONTENT_TYPE))
    };
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        challenge,
        content_type,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

async fn bearer(app: &Router, token: &str) -> Answer {
    send(
        app,
        Some((header::AUTHORIZATION, format!("Bearer {token}"))),
    )
    .await
}

fn assert_unauthenticated(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{}", answer.body);
    assert_eq!(answer.challenge.as_deref(), Some("Bearer"));
    assert_eq!(
        answer.content_type.as_deref(),
        Some("application/problem+json")
    );
    let problem: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(
        problem,
        json!({
            "type": "about:blank",
            "title": "Unauthorized",
            "status": 401,
            "detail": "A valid bearer token is required.",
        })
    );
}

async fn revoke(pool: &PgPool) {
    let revocation = SessionRevocation {
        id: SessionRevocationId::parse("0190f2a8-7b3c-7d4e-8f00-000000000007").unwrap(),
        session: SessionId::new(REVOKED_SESSION).unwrap(),
        user: Uuid::parse(USER_ID).unwrap(),
        source: RevocationSource::UserService,
        revoked_by: ActorRef::parse("system:user-service").unwrap(),
        revoked_at: at(NOW),
        prune_after: at(NOW + 900),
    };
    PgRevocationRepository::new(pool.clone())
        .revoke_session(&revocation)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_request_without_authorization_is_the_401_problem(pool: PgPool) {
    let key = TestKey::generate();
    let app = app(&pool, "authentication-missing", &key).await;

    assert_unauthenticated(&send(&app, None).await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_valid_user_token_and_a_valid_service_token_pass(pool: PgPool) {
    let key = TestKey::generate();
    let app = app(&pool, "authentication-valid", &key).await;

    let user = bearer(&app, &key.sign(&user_claims())).await;
    let service = bearer(&app, &key.sign(&service_claims())).await;

    assert_eq!(user.status, StatusCode::OK);
    assert_eq!(user.body, USER_ID);
    assert_eq!(service.status, StatusCode::OK);
    assert_eq!(service.body, "user-service");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_token_without_the_caller_audience_or_living_too_long_is_refused(pool: PgPool) {
    let key = TestKey::generate();
    let app = app(&pool, "authentication-service", &key).await;
    let foreign = with(service_claims(), "aud", json!(AUDIENCE));
    let long_lived = with(service_claims(), "exp", json!(NOW + 601));

    assert_unauthenticated(&bearer(&app, &key.sign(&foreign)).await);
    assert_unauthenticated(&bearer(&app, &key.sign(&long_lived)).await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn malformed_expired_and_revoked_tokens_are_the_same_401_problem(pool: PgPool) {
    let key = TestKey::generate();
    let app = app(&pool, "authentication-refused", &key).await;
    revoke(&pool).await;
    let malformed = unsigned(&json!({"alg": "RS256", "typ": "JWT"}), &user_claims());
    let expired = key.sign(&with(
        with(user_claims(), "iat", json!(NOW - 900)),
        "exp",
        json!(NOW - 31),
    ));
    let revoked = key.sign(&with(user_claims(), "sid", json!(REVOKED_SESSION)));

    for token in [
        "not-a-jws",
        malformed.as_str(),
        expired.as_str(),
        revoked.as_str(),
    ] {
        assert_unauthenticated(&bearer(&app, token).await);
    }
    assert_eq!(
        bearer(&app, &key.sign(&user_claims())).await.status,
        StatusCode::OK
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_token_in_the_cookie_is_authenticated_like_a_bearer_token(pool: PgPool) {
    let key = TestKey::generate();
    let app = app(&pool, "authentication-cookie", &key).await;
    revoke(&pool).await;
    let valid = key.sign(&user_claims());
    let revoked = key.sign(&with(user_claims(), "sid", json!(REVOKED_SESSION)));

    let accepted = send(
        &app,
        Some((header::COOKIE, format!("{AUTH_COOKIE}={valid}"))),
    )
    .await;
    let refused = send(
        &app,
        Some((header::COOKIE, format!("{AUTH_COOKIE}={revoked}"))),
    )
    .await;

    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.body, USER_ID);
    assert_unauthenticated(&refused);
}
