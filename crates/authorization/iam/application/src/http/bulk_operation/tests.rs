//! Tests of the REST reads of the bulk operations.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

use crate::bulk_operation_fixtures::{
    COMPLETED, REQUESTER, RUNNING, UNKNOWN, asked_count, scenario, stored,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};

fn app(failure: Option<fn() -> IamError>) -> (Router, crate::bulk_operation_fixtures::Asked) {
    let (state, asked) = scenario(stored(), failure);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn get(uri: &str, authenticated: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    if authenticated {
        request.extensions_mut().insert(principal());
    }
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

#[tokio::test]
async fn a_running_operation_is_read_with_its_progress() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get(&format!("/bulk-operations/{RUNNING}"), true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], RUNNING);
    assert_eq!(body["kind"], "role_deletion");
    assert_eq!(body["status"], "running");
    assert_eq!(body["appliedRecords"], 1_000);
    assert_eq!(body["totalRecords"], 2_500);
    assert_eq!(body["firstVersion"], 4);
    assert_eq!(body["lastVersion"], 5);
    assert_eq!(body["requester"], REQUESTER);
    assert_eq!(body["propagation"], Value::Null);
}

#[tokio::test]
async fn an_unknown_operation_is_a_404_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get(&format!("/bulk-operations/{UNKNOWN}"), true)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/bulk-operations/nope", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "id");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_operations_are_listed_oldest_first() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get("/bulk-operations", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], RUNNING);
    assert_eq!(body["items"][1]["id"], COMPLETED);
    assert_eq!(body["items"][1]["status"], "completed");
    assert!(body.get("nextCursor").is_none());
}

#[tokio::test]
async fn a_page_of_one_names_the_cursor_of_the_next_page() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get("/bulk-operations?limit=1", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["nextCursor"], RUNNING);
}

#[tokio::test]
async fn the_cursor_continues_after_the_operation_it_names() {
    let (app, _asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/bulk-operations?limit=1&after={RUNNING}"), true),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], COMPLETED);
}

#[tokio::test]
async fn an_invalid_limit_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, _body) = answer(app, get("/bulk-operations?limit=0", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_storage_failure_is_a_500_problem() {
    let (app, _asked) = app(Some(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, get("/bulk-operations", true)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_storage_failure_of_a_read_by_id_is_a_500_problem() {
    let (app, asked) = app(Some(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, get(&format!("/bulk-operations/{RUNNING}"), true)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(asked_count(&asked), 1);
}

#[tokio::test]
async fn a_caller_that_is_not_authenticated_is_refused() {
    let (app, asked) = app(None);

    let (status, _body) = answer(app, get("/bulk-operations", false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(asked_count(&asked), 0);
}
