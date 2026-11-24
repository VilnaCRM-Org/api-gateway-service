use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::RequestDigester as _;
use serde_json::{Value, json};
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::command::set_global_token_cutoff::SetGlobalTokenCutoffCommand;
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::global_token_cutoff::dto::SetGlobalTokenCutoffRequest;
use crate::http::{IamState, router};
use crate::revocation_fixtures::{Answers, Dispatched, TARGET, receipt, recorded, scenario};

fn app(answers: Answers) -> (Router, Dispatched<SetGlobalTokenCutoffCommand>) {
    let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), dispatched)
}

fn set(body: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/global-token-cutoffs")
        .header(CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request.extensions_mut().insert(principal());
    request
}

async fn answer(app: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_cutoff_is_201_with_the_policy_version_and_reaches_the_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, headers, result) = answer(app, set("{}", None)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "41");
    assert_eq!(result["id"], json!(TARGET));
    assert_eq!(result["policyVersion"], json!(41));
    let sent = recorded(&dispatched);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].idempotency.is_none());
}

#[tokio::test]
async fn the_idempotency_key_and_the_request_digest_reach_the_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, set("{}", Some("cutoff-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    let idempotency = recorded(&dispatched)[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "cutoff-1");
    assert_eq!(
        idempotency.request_digest,
        FakeRequestDigester.digest(SetGlobalTokenCutoffRequest::canonical_form())
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let (app, dispatched) = app(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let (status, _headers, result) = answer(app, set("{}", Some("cutoff-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["id"], json!(TARGET));
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn an_unknown_body_field_is_refused_without_a_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, set(r#"{"at": "2026-01-01T00:00:00Z"}"#, None)).await;

    assert!(status.is_client_error());
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_request_without_a_caller_is_401() {
    let (app, dispatched) = app(Answers::default());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/global-token-cutoffs")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let (status, ..) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_failing_command_is_500() {
    let (app, _dispatched) = app(Answers {
        command: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(app, set("{}", None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
