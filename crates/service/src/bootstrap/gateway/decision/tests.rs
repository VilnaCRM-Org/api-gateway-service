use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock as _, BootInstant, FreshnessRule, PolicyVersion};
use serde_json::{Value, json};
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::decision_snapshot::DecisionSnapshot;
use test_support::policy_view::FakePolicyView;

use super::*;
use crate::cli::GatewayArgs;

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    GatewayConfig::from_args(&args).unwrap()
}

fn ports(fresh: bool) -> DecisionPorts {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    ));
    if fresh {
        state.attach(
            FreshnessProof {
                taken_at: clock.now(),
                watermark: 1,
            },
            PolicyVersion::new(1).unwrap(),
        );
    }
    let snapshot = DecisionSnapshot::at(PolicyVersion::new(1).unwrap());
    DecisionPorts {
        view: Arc::new(FakePolicyView::with_snapshot(Arc::new(snapshot))),
        freshness: state,
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    }
}

fn decision_router(fresh: bool) -> Router {
    router(&config(), ports(fresh)).unwrap()
}

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    content_type: Option<String>,
    body: Value,
}

async fn post(app: &Router, path: &str, body: &Value) -> Answer {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = response.headers().clone();
    let header = |name| {
        headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    };
    let challenge = header(WWW_AUTHENTICATE);
    let content_type = header(CONTENT_TYPE);
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        challenge,
        content_type,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn check(request_id: &str) -> Value {
    json!({
        "credential": "subject-token",
        "service": "orders",
        "permissions": ["rest:orders:GET /api/orders"],
        "requestId": request_id,
    })
}

#[tokio::test]
async fn a_request_without_a_token_is_the_401_problem_with_the_bearer_challenge() {
    let app = decision_router(true);

    for path in [
        "/api/access-validations",
        "/api/access-validations/batch",
        "/api/token-resolutions",
    ] {
        let answer = post(&app, path, &check("request-1")).await;

        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(answer.challenge.as_deref(), Some("Bearer"), "{path}");
        assert_eq!(
            answer.content_type.as_deref(),
            Some("application/problem+json"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn no_management_route_is_served() {
    let app = decision_router(true);

    for path in [
        "/api/roles",
        "/api/routes",
        "/api/upstreams",
        "/internal/freshness",
    ] {
        let answer = post(&app, path, &json!({})).await;

        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn a_graphql_management_field_is_never_resolved_without_a_token() {
    let app = decision_router(true);
    let query = json!({ "query": "{ role(id: \"1\") { id } }" });

    let answer = post(&app, "/api/graphql", &query).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["data"], Value::Null);
    assert!(answer.body["errors"][0]["message"].is_string());
}

#[tokio::test]
async fn a_graphql_decision_field_without_a_token_is_unauthenticated() {
    let app = decision_router(true);
    let query = json!({
        "query": "{ resolveToken(input: { credential: \"x\" }) { resolved } }"
    });

    let answer = post(&app, "/api/graphql", &query).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.body["errors"][0]["extensions"]["code"],
        "UNAUTHENTICATED"
    );
}

#[tokio::test]
async fn a_stale_snapshot_answers_every_check_with_deny_and_unavailable_without_a_token() {
    let app = decision_router(false);

    let single = post(&app, "/api/access-validations", &check("request-1")).await;
    let batch = post(
        &app,
        "/api/access-validations/batch",
        &json!({ "checks": [check("request-1"), check("request-2")] }),
    )
    .await;

    assert_eq!(single.status, StatusCode::OK);
    assert_eq!(single.body["decision"], "deny");
    assert_eq!(single.body["reason"], "unavailable");
    assert_eq!(single.body["requestId"], "request-1");
    assert_eq!(batch.status, StatusCode::OK);
    let results = batch.body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for result in results {
        assert_eq!(result["decision"], "deny");
        assert_eq!(result["reason"], "unavailable");
    }
}

#[tokio::test]
async fn a_batch_of_101_checks_is_the_422_problem_even_on_a_stale_snapshot() {
    let app = decision_router(false);
    let checks: Vec<Value> = (0..101).map(|n| check(&format!("request-{n}"))).collect();

    let answer = post(
        &app,
        "/api/access-validations/batch",
        &json!({ "checks": checks }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn token_resolution_is_not_decided_by_a_stale_pod() {
    let app = decision_router(false);

    let answer = post(
        &app,
        "/api/token-resolutions",
        &json!({ "credential": "subject-token" }),
    )
    .await;

    assert_ne!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn a_key_file_that_cannot_be_parsed_fails_the_setup() {
    let mut config = config();
    config.tokens.public_keys_file = PathBuf::from("/nonexistent/keys.pem");

    let outcome = router(&config, ports(true));

    assert!(matches!(outcome, Err(DecisionSetupError::Keys(_))));
}

#[tokio::test]
async fn a_graphql_body_without_a_query_is_the_422_problem() {
    let app = decision_router(true);

    let answer = post(&app, "/api/graphql", &json!({ "variables": {} })).await;

    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn the_handler_of_the_rejections_is_registered_once() {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH));
    let once = register_rejections(InMemoryCommandBus::new(), &clock).unwrap();

    let twice = register_rejections(once, &clock);

    assert!(matches!(twice, Err(DecisionSetupError::Handlers(_))));
}

#[test]
fn the_discarded_rejections_hold_nothing_to_drain_or_requeue() {
    let log = DiscardedRejections;

    log.requeue(Vec::new());

    assert_eq!(log.drain(SystemTime::UNIX_EPOCH), Vec::new());
}
