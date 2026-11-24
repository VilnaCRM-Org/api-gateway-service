use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{RequestDigester as _, SessionId};
use serde_json::{Value, json};
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::command::revoke_sessions::RevokeSessionsCommand;
use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::http::session_revocation::dto::RevokeSessionsRequest;
use crate::http::{IamState, router};
use crate::revocation_fixtures::{
    Answers, Dispatched, Refusal, TARGET, receipt, recorded, scenario,
};

fn app(answers: Answers) -> (Router, Dispatched<RevokeSessionsCommand>) {
    let (state, dispatched) = scenario::<RevokeSessionsCommand>(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), dispatched)
}

fn revoke(body: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/session-revocations")
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

fn body(sessions: &[&str]) -> String {
    json!({ "userId": USER, "sessionIds": sessions }).to_string()
}

#[tokio::test]
async fn a_revocation_is_201_with_the_policy_version_and_reaches_the_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, headers, result) = answer(app, revoke(&body(&["sid-1", "sid-2"]), None)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "41");
    assert_eq!(result["id"], json!(TARGET));
    assert_eq!(result["policyVersion"], json!(41));
    let sent = recorded(&dispatched);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user_id.to_string(), USER);
    let sessions: Vec<_> = sent[0].session_ids.iter().map(SessionId::as_str).collect();
    assert_eq!(sessions, ["sid-1", "sid-2"]);
    assert!(sent[0].idempotency.is_none());
}

#[tokio::test]
async fn a_missing_session_list_is_the_cutoff_of_the_user() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, revoke(&json!({ "userId": USER }).to_string(), None)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(recorded(&dispatched)[0].session_ids.len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_the_request_digest_reach_the_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(app, revoke(&body(&["sid-1"]), Some("revoke-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    let idempotency = recorded(&dispatched)[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "revoke-1");
    let request = RevokeSessionsRequest {
        user_id: USER.to_owned(),
        session_ids: vec!["sid-1".to_owned()],
    };
    assert_eq!(
        idempotency.request_digest,
        FakeRequestDigester.digest(&request.canonical_form())
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let (app, dispatched) = app(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let (status, _headers, result) = answer(app, revoke(&body(&["sid-1"]), Some("revoke-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["id"], json!(TARGET));
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn an_invalid_user_or_session_is_422_without_a_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, _headers, problem) = answer(
        app,
        revoke(
            &json!({ "userId": "nobody", "sessionIds": ["ok", ""] }).to_string(),
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let paths: Vec<_> = problem["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|violation| violation["propertyPath"].clone())
        .collect();
    assert_eq!(paths, [json!("sessionIds[1]"), json!("userId")]);
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn an_unknown_body_field_is_refused_without_a_command() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(
        app,
        revoke(&json!({ "userId": USER, "all": true }).to_string(), None),
    )
    .await;

    assert!(status.is_client_error());
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_request_without_a_caller_is_401() {
    let (app, dispatched) = app(Answers::default());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/session-revocations")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body(&[])))
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

        let (status, ..) = answer(app, revoke(&body(&["sid-1"]), None)).await;

        assert_eq!(status, expected);
    }
}
