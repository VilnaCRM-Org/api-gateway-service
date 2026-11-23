use axum::Router;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use iam_domain::{AccessTarget, DecisionOutcome, DecisionReason, HttpMethod, PolicyVersion};
use rstest::rstest;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::access_validation_fixtures::{
    Asked, AskedBatches, DECISION, PROJECT, Refusal, SUBJECT, allowed, allowed_in_project,
    batch_scenario, denied, recorded, recorded_batches, scenario, token_refused,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};
use crate::query::validate_access_batch::BatchCheck;

fn app(answer: Result<DecisionOutcome, Refusal>) -> (Router, Asked) {
    let (state, asked) = scenario(answer);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn post(body: &Value) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/access-validations")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

async fn answer(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn rest_body() -> Value {
    json!({
        "credential": "subject-token",
        "service": "billing",
        "rest": {"method": "GET", "path": "/api/invoices/42"},
        "requestId": "req-1"
    })
}

#[tokio::test]
async fn an_allowed_check_is_a_200_decision_body_that_echoes_the_request_id() {
    let (app, asked) = app(Ok(allowed()));

    let (status, body) = answer(app, post(&rest_body())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "decision": "allow",
            "reason": "allowed",
            "denied": [],
            "scopes": "all",
            "subject": {"id": SUBJECT, "kind": "user"},
            "decisionId": DECISION,
            "policyVersion": 7,
            "requestId": "req-1"
        })
    );
    let [query] = recorded(&asked).try_into().unwrap();
    assert_eq!(query.credential.expose(), "subject-token");
    assert_eq!(query.check.service().as_str(), "billing");
    let AccessTarget::Rest(target) = query.check.target() else {
        panic!("expected a REST target");
    };
    assert_eq!(target.method(), HttpMethod::Get);
    assert_eq!(target.path(), "/api/invoices/42");
}

#[tokio::test]
async fn a_check_of_keys_in_a_project_passes_the_project_and_lists_it_in_the_scopes() {
    let (app, asked) = app(Ok(allowed_in_project()));
    let mut body = json!({
        "credential": "t", "service": "billing", "requestId": "req-2",
        "permissions": ["rest:billing:GET /api/invoices"],
        "projectId": PROJECT, "minPolicyVersion": 7
    });
    body["credential"] = json!("subject-token");

    let (status, answered) = answer(app, post(&body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(answered["scopes"], json!([PROJECT]));
    let [query] = recorded(&asked).try_into().unwrap();
    assert_eq!(query.check.project().unwrap().to_string(), PROJECT);
    assert_eq!(
        query.check.min_policy_version(),
        Some(PolicyVersion::new(7).unwrap())
    );
    let AccessTarget::Permissions(target) = query.check.target() else {
        panic!("expected a permissions target");
    };
    assert_eq!(target.keys(), ["rest:billing:GET /api/invoices"]);
}

#[rstest]
#[case::permission_missing(DecisionReason::PermissionMissing)]
#[case::scope_missing(DecisionReason::ScopeMissing)]
#[case::unknown_operation(DecisionReason::UnknownOperation)]
#[case::malformed_operation(DecisionReason::MalformedOperation)]
#[case::unknown_service(DecisionReason::UnknownService)]
#[case::unavailable(DecisionReason::Unavailable)]
#[tokio::test]
async fn a_denied_check_is_still_a_200_with_the_reason_and_the_denied_keys(
    #[case] reason: DecisionReason,
) {
    let (app, _asked) = app(Ok(denied(reason, &["rest:billing:GET /api/invoices/{}"])));

    let (status, body) = answer(app, post(&rest_body())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], json!("deny"));
    assert_eq!(body["reason"], json!(reason.as_str()));
    assert_eq!(body["denied"], json!(["rest:billing:GET /api/invoices/{}"]));
    assert_eq!(body["scopes"], json!([]));
}

#[tokio::test]
async fn a_refused_token_is_a_200_deny_without_a_subject() {
    let (app, _asked) = app(Ok(token_refused()));

    let (status, body) = answer(app, post(&rest_body())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["reason"], json!("token_expired"));
    assert!(body.get("subject").is_none());
}

fn keys(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("rest:billing:GET /api/invoices/{index}"))
        .collect()
}

#[rstest]
#[case::no_target(json!({"credential": "t", "service": "billing", "requestId": "r"}), "target")]
#[case::two_targets(json!({
    "credential": "t", "service": "billing", "requestId": "r",
    "rest": {"method": "GET", "path": "/"}, "permissions": ["iam:validate:*"]
}), "target")]
#[case::too_many_keys(json!({
    "credential": "t", "service": "billing", "requestId": "r", "permissions": keys(101)
}), "permissions")]
#[case::no_keys(json!({
    "credential": "t", "service": "billing", "requestId": "r", "permissions": []
}), "permissions")]
#[case::service(json!({
    "credential": "t", "service": "Not A Service", "requestId": "r",
    "permissions": ["iam:validate:*"]
}), "service")]
#[case::project(json!({
    "credential": "t", "service": "billing", "requestId": "r",
    "permissions": ["iam:validate:*"], "projectId": "nope"
}), "projectId")]
#[case::negative_version(json!({
    "credential": "t", "service": "billing", "requestId": "r",
    "permissions": ["iam:validate:*"], "minPolicyVersion": -1
}), "minPolicyVersion")]
#[tokio::test]
async fn an_invalid_request_is_a_422_problem_naming_the_property_and_asks_nothing(
    #[case] body: Value,
    #[case] property: &str,
) {
    let (app, asked) = app(Ok(allowed()));

    let (status, answered) = answer(app, post(&body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answered["violations"][0]["propertyPath"], json!(property));
    assert_eq!(recorded(&asked).len(), 0);
}

#[tokio::test]
async fn a_minimum_version_that_the_handler_refuses_is_a_422_problem() {
    let (app, _asked) = app(Err(|| {
        IamError::invalid_property("minPolicyVersion", "Too new.", "range")
    }));

    let (status, body) = answer(app, post(&rest_body())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("minPolicyVersion")
    );
}

#[tokio::test]
async fn a_storage_failure_of_the_bus_is_an_internal_problem() {
    let (app, _asked) = app(Err(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, post(&rest_body())).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_request_without_a_token_is_the_401_problem() {
    let (app, asked) = app(Ok(allowed()));
    let mut request = post(&rest_body());
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, body) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(recorded(&asked).len(), 0);
}

#[tokio::test]
async fn the_credential_is_never_echoed() {
    let (app, _asked) = app(Ok(allowed()));

    let response = app.oneshot(post(&rest_body())).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    assert!(!String::from_utf8_lossy(&bytes).contains("subject-token"));
}

fn batch_app(answer: Result<Vec<DecisionOutcome>, Refusal>) -> (Router, AskedBatches) {
    let (state, asked) = batch_scenario(answer);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

/// The batch route as the composition root serves it, under the 64 KiB default of every route.
fn batch_app_under_the_default_limit(
    answer: Result<Vec<DecisionOutcome>, Refusal>,
) -> (Router, AskedBatches) {
    let (state, asked) = batch_scenario(answer);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (
        routes
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(state),
        asked,
    )
}

fn post_batch(body: &Value) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/access-validations/batch")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

fn rest_item(request_id: &str) -> Value {
    let mut item = rest_body();
    item["requestId"] = json!(request_id);
    item
}

#[tokio::test]
async fn a_batch_is_a_200_with_one_result_per_check_in_request_order() {
    let outcomes = vec![
        allowed(),
        denied(DecisionReason::PermissionMissing, &["key"]),
        token_refused(),
    ];
    let (app, asked) = batch_app(Ok(outcomes));
    let body = json!({"checks": [rest_item("a"), rest_item("b"), rest_item("c")]});

    let (status, answered) = answer(app, post_batch(&body)).await;

    assert_eq!(status, StatusCode::OK);
    let results = answered["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["decision"], json!("allow"));
    assert_eq!(results[0]["requestId"], json!("a"));
    assert_eq!(results[0]["decisionId"], json!(DECISION));
    assert_eq!(results[1]["reason"], json!("permission_missing"));
    assert_eq!(results[1]["requestId"], json!("b"));
    assert_eq!(results[2]["reason"], json!("token_expired"));
    assert_eq!(results[2]["requestId"], json!("c"));
    let [batch] = recorded_batches(&asked).try_into().unwrap();
    assert_eq!(batch.len(), 3);
    assert!(
        batch
            .iter()
            .all(|item| matches!(item, BatchCheck::Valid(_)))
    );
}

#[tokio::test]
async fn a_malformed_item_is_asked_as_malformed_and_keeps_its_request_id() {
    let (app, asked) = batch_app(Ok(vec![
        allowed(),
        denied(DecisionReason::MalformedOperation, &[]),
    ]));
    let mut broken = rest_item("broken");
    broken["rest"]["method"] = json!("FETCH");
    let body = json!({"checks": [rest_item("fine"), broken]});

    let (status, answered) = answer(app, post_batch(&body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answered["results"][1]["reason"],
        json!("malformed_operation")
    );
    assert_eq!(answered["results"][1]["requestId"], json!("broken"));
    let [batch] = recorded_batches(&asked).try_into().unwrap();
    assert!(matches!(
        batch.as_slice(),
        [BatchCheck::Valid(_), BatchCheck::Malformed]
    ));
}

#[rstest]
#[case::empty(0)]
#[case::one_hundred_and_one(101)]
#[tokio::test]
async fn a_batch_of_no_check_or_of_too_many_is_a_422_problem_and_asks_nothing(
    #[case] count: usize,
) {
    let (app, asked) = batch_app(Ok(Vec::new()));
    let checks: Vec<Value> = (0..count)
        .map(|index| rest_item(&index.to_string()))
        .collect();

    let (status, answered) = answer(app, post_batch(&json!({"checks": checks}))).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answered["violations"][0]["propertyPath"], json!("checks"));
    assert_eq!(recorded_batches(&asked).len(), 0);
}

#[tokio::test]
async fn a_batch_of_one_hundred_checks_is_asked_whole() {
    let outcomes = vec![allowed(); 100];
    let (app, asked) = batch_app(Ok(outcomes));
    let checks: Vec<Value> = (0..100)
        .map(|index| rest_item(&index.to_string()))
        .collect();

    let (status, answered) = answer(app, post_batch(&json!({"checks": checks}))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(answered["results"].as_array().unwrap().len(), 100);
    assert_eq!(recorded_batches(&asked)[0].len(), 100);
}

#[tokio::test]
async fn a_storage_failure_of_the_bus_is_an_internal_problem_for_a_batch() {
    let (app, _asked) = batch_app(Err(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, post_batch(&json!({"checks": [rest_item("a")]}))).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_batch_without_a_token_is_the_401_problem() {
    let (app, asked) = batch_app(Ok(vec![allowed()]));
    let mut request = post_batch(&json!({"checks": [rest_item("a")]}));
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, _body) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(recorded_batches(&asked).len(), 0);
}

#[tokio::test]
async fn the_credentials_of_a_batch_are_never_echoed() {
    let (app, _asked) = batch_app(Ok(vec![allowed()]));

    let response = app
        .oneshot(post_batch(&json!({"checks": [rest_item("a")]})))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    assert!(!String::from_utf8_lossy(&bytes).contains("subject-token"));
}

#[tokio::test]
async fn a_batch_of_too_many_checks_with_the_longest_credentials_is_still_read_and_refused() {
    let (app, asked) = batch_app_under_the_default_limit(Ok(Vec::new()));
    let checks: Vec<Value> = (0..101)
        .map(|index| {
            let mut item = rest_item(&index.to_string());
            item["credential"] = json!("c".repeat(8_192));
            item
        })
        .collect();

    let (status, answered) = answer(app, post_batch(&json!({"checks": checks}))).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answered["violations"][0]["propertyPath"], json!("checks"));
    assert_eq!(recorded_batches(&asked).len(), 0);
}

#[tokio::test]
async fn a_batch_body_above_the_limit_of_the_route_is_413() {
    let (app, asked) = batch_app_under_the_default_limit(Ok(Vec::new()));
    let mut item = rest_item("0");
    item["credential"] = json!("c".repeat(super::ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES));

    let (status, _answered) = answer(app, post_batch(&json!({"checks": [item]}))).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(recorded_batches(&asked).len(), 0);
}
