use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use iam_domain::{ProjectId, ServiceName, SubjectRef};
use serde_json::Value;
use shared_domain::Uuid;
use test_support::bus::FakeQueryBus;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::http::{IamState, router};
use crate::query::get_user_role_permissions::{
    GetUserRolePermissionsQuery, UserRolePermissionsView,
};
use crate::user_role_permission_fixtures::{
    Asked, PROJECT, Refusal, recorded, scenario, view, view_json,
};
use std::sync::Arc;

fn app(answer: Result<UserRolePermissionsView, Refusal>) -> (Router, Arc<FakeQueryBus>, Asked) {
    let (state, queries, asked) = scenario(answer);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), queries, asked)
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

fn path(suffix: &str) -> String {
    format!("/users/{USER}/role-permissions{suffix}")
}

#[tokio::test]
async fn the_effective_permissions_are_listed_with_roles_scopes_expiry_and_policy_version() {
    let (app, queries, asked) = app(Ok(view()));

    let (status, body) = answer(app, get(&path(""), true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, view_json());
    assert_eq!(queries.asked(), ["GetUserRolePermissionsQuery"]);
    assert_eq!(
        recorded(&asked),
        [GetUserRolePermissionsQuery {
            subject: SubjectRef::user(Uuid::parse(USER).unwrap()),
            project: None,
            service: None,
        }]
    );
}

#[tokio::test]
async fn the_project_and_the_service_reach_the_query() {
    let (app, _queries, asked) = app(Ok(view()));

    let (status, _body) = answer(
        app,
        get(
            &path(&format!("?projectId={PROJECT}&service=billing")),
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let query = recorded(&asked).pop().unwrap();
    assert_eq!(query.project, Some(ProjectId::parse(PROJECT).unwrap()));
    assert_eq!(query.service, Some(ServiceName::new("billing").unwrap()));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_validation_failure_naming_the_user() {
    let (app, queries, _asked) = app(Ok(view()));

    let (status, body) = answer(app, get("/users/not-a-uuid/role-permissions", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "userId");
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_invalid_project_is_a_validation_failure_naming_the_project() {
    let (app, _queries, _asked) = app(Ok(view()));

    let (status, body) = answer(app, get(&path("?projectId=nope"), true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "projectId");
}

#[tokio::test]
async fn an_unknown_query_parameter_is_refused() {
    let (app, _queries, _asked) = app(Ok(view()));

    let (status, _body) = answer(app, get(&path("?colour=red"), true)).await;

    assert!(status.is_client_error());
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_refused() {
    let (app, queries, _asked) = app(Ok(view()));

    let (status, body) = answer(app, get(&path(""), false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], 401);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_storage_failure_is_a_500_problem() {
    let (app, _queries, _asked) = app(Err(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, get(&path(""), true)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
