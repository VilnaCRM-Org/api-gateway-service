use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use iam_domain::{AccessTarget, DecisionOutcome, DecisionReason, HttpMethod, PolicyVersion};
use rstest::rstest;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::access_validation_fixtures::{
    Asked, DECISION, PROJECT, Refusal, SUBJECT, allowed, allowed_in_project, denied, recorded,
    scenario, token_refused,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};

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
