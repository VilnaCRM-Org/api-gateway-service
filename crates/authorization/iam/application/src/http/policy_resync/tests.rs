use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::RequestDigester as _;
use rstest::rstest;
use serde_json::{Value, json};
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::policy_resync::dto::ResyncPolicyRequest;
use crate::http::{IamState, router};
use crate::policy_resync_fixtures::{
    Answers, Dispatched, OPERATION, Refusal, operation, receipt, recorded, scenario,
};

fn app(answers: Answers) -> (Router, Dispatched) {
    let (state, dispatched) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), dispatched)
}

fn resync(body: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/policy-resyncs")
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
async fn a_resync_is_202_with_the_bulk_operation_and_its_location() {
    let (app, dispatched) = app(Answers::default());

    let (status, headers, body) = answer(
        app,
        resync(r#"{"reason": "The topic lost records."}"#, None),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        headers.get("location").unwrap(),
        &format!("/api/bulk-operations/{OPERATION}")
    );
    assert_eq!(body["id"], json!(OPERATION));
    assert_eq!(body["kind"], json!("resync"));
    assert_eq!(body["status"], json!("pending"));
    assert_eq!(body["totalRecords"], json!(2_500));
    assert_eq!(body["appliedRecords"], json!(0));
    let sent = recorded(&dispatched);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].reason, "The topic lost records.");
    assert!(sent[0].idempotency.is_none());
}

#[tokio::test]
async fn the_idempotency_key_and_the_request_digest_reach_the_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, resync(r#"{"reason": "again"}"#, Some("resync-1"))).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    let sent = recorded(&dispatched);
    let idempotency = sent[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "resync-1");
    let request = ResyncPolicyRequest {
        reason: "again".to_owned(),
    };
    assert_eq!(
        idempotency.request_digest,
        FakeRequestDigester.digest(&request.canonical_form())
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_bulk_operation_without_a_command() {
    let (app, dispatched) = app(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let (status, headers, body) =
        answer(app, resync(r#"{"reason": "again"}"#, Some("resync-1"))).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["id"], json!(OPERATION));
    assert_eq!(
        headers.get("location").unwrap(),
        &format!("/api/bulk-operations/{OPERATION}")
    );
    assert!(recorded(&dispatched).is_empty());
}

#[rstest]
#[case::missing("{}")]
#[case::empty(r#"{"reason": ""}"#)]
#[case::blank(r#"{"reason": "   "}"#)]
#[case::two_lines(r#"{"reason": "first\nsecond"}"#)]
#[tokio::test]
async fn a_missing_or_unusable_reason_is_422_without_a_command(#[case] body: &str) {
    let (app, dispatched) = app(Answers::default());

    let (status, _headers, problem) = answer(app, resync(body, None)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("reason"));
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn an_unknown_body_field_is_refused_without_a_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, resync(r#"{"reason": "x", "force": true}"#, None)).await;

    assert!(status.is_client_error());
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_a_422_violation() {
    let (app, _dispatched) = app(Answers::default());

    let (status, _headers, body) = answer(app, resync(r#"{"reason": "x"}"#, Some(""))).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("idempotencyKey")
    );
}

#[tokio::test]
async fn a_request_without_a_caller_is_401() {
    let (app, dispatched) = app(Answers::default());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/policy-resyncs")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"reason": "x"}"#))
        .unwrap();

    let (status, ..) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_refused_command_is_its_problem() {
    let refusals: [(Refusal, StatusCode); 2] = [
        (|| IamError::Conflict, StatusCode::CONFLICT),
        (
            || IamError::Storage("database unavailable".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (refusal, expected) in refusals {
        let (app, _dispatched) = app(Answers {
            command: Err(refusal),
            ..Answers::default()
        });

        let (status, ..) = answer(app, resync(r#"{"reason": "x"}"#, None)).await;

        assert_eq!(status, expected);
    }
}

#[tokio::test]
async fn an_operation_that_cannot_be_found_after_the_command_is_404() {
    let (app, _dispatched) = app(Answers {
        operation: Ok(None),
        ..Answers::default()
    });

    let (status, ..) = answer(app, resync(r#"{"reason": "x"}"#, None)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_operation_that_cannot_be_read_after_the_command_is_500() {
    let (app, dispatched) = app(Answers {
        operation: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(app, resync(r#"{"reason": "x"}"#, None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(recorded(&dispatched).len(), 1);
}

#[test]
fn the_location_is_the_path_of_the_operation() {
    assert_eq!(
        super::location(&operation()),
        format!("/api/bulk-operations/{OPERATION}")
    );
}
