//! A missing entity version is a 428 problem (GraphQL `PRECONDITION_REQUIRED`) and a stale one a
//! 412 problem (GraphQL `PRECONDITION_FAILED`), end to end through `IfMatchHeader`, the `IamError`
//! mapping and `iam_problem_to_graphql_error`.

use async_graphql::{EmptySubscription, Error, Object, Request as GraphqlRequest, Schema, Value};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::header::{CONTENT_TYPE, IF_MATCH};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse as _;
use axum::routing::put;
use iam_application::IamError;
use iam_application::graphql::{expected_version, iam_problem_to_graphql_error};
use iam_application::http::extract::IfMatchHeader;
use iam_domain::EntityVersion;
use shared_application::http::{PROBLEM_CONTENT_TYPE, Problem};
use tower::ServiceExt as _;

/// The version the probe record currently has.
const CURRENT: i64 = 3;

fn current() -> EntityVersion {
    EntityVersion::new(CURRENT).unwrap()
}

/// Applies a change that expects `expected` to the probe record, as an update command does.
fn apply(expected: EntityVersion) -> Result<EntityVersion, IamError> {
    current().check(Some(expected))?;
    Ok(expected)
}

/// An update route that reads `If-Match` and applies the change.
fn router() -> Router {
    Router::new().route(
        "/probe",
        put(
            async |IfMatchHeader(expected): IfMatchHeader| match apply(expected) {
                Ok(_version) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => Problem::from(error).into_response(),
            },
        ),
    )
}

async fn send(if_match: Option<&str>) -> (StatusCode, String, String) {
    let mut builder = Request::builder().method("PUT").uri("/probe");
    if let Some(value) = if_match {
        builder = builder.header(IF_MATCH, value);
    }
    let response = router()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem() {
    let (status, content_type, body) = send(None).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(content_type, PROBLEM_CONTENT_TYPE);
    assert!(body.contains("\"status\":428"), "{body}");
}

#[tokio::test]
async fn an_update_with_a_stale_if_match_is_the_412_problem() {
    let (status, content_type, body) = send(Some("\"2\"")).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(content_type, PROBLEM_CONTENT_TYPE);
    assert!(body.contains("\"status\":412"), "{body}");
}

#[tokio::test]
async fn an_update_with_the_current_if_match_is_applied() {
    let (status, _content_type, body) = send(Some("\"3\"")).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty(), "{body}");
}

struct ProbeQuery;

#[Object]
impl ProbeQuery {
    async fn version(&self) -> i64 {
        std::future::ready(CURRENT).await
    }
}

struct ProbeMutation;

#[Object]
impl ProbeMutation {
    /// An update whose input names the version it changes.
    async fn update(&self, expected_version: Option<i64>) -> Result<i64, Error> {
        std::future::ready(expected_version_of(expected_version))
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

fn expected_version_of(field: Option<i64>) -> Result<i64, Problem> {
    let expected = expected_version(field)?;
    let applied = apply(expected)?;
    Ok(applied.value())
}

async fn execute(query: &str) -> async_graphql::Response {
    Schema::new(ProbeQuery, ProbeMutation, EmptySubscription)
        .execute(GraphqlRequest::new(query))
        .await
}

fn first_code(response: &async_graphql::Response) -> Option<Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

#[tokio::test]
async fn a_graphql_update_without_expected_version_is_precondition_required() {
    let response = execute("mutation { update }").await;

    assert_eq!(
        first_code(&response),
        Some(Value::String("PRECONDITION_REQUIRED".to_owned()))
    );
}

#[tokio::test]
async fn a_graphql_update_with_a_stale_expected_version_is_precondition_failed() {
    let response = execute("mutation { update(expectedVersion: 2) }").await;

    assert_eq!(
        first_code(&response),
        Some(Value::String("PRECONDITION_FAILED".to_owned()))
    );
}

#[tokio::test]
async fn a_graphql_update_with_the_current_expected_version_is_applied() {
    let response = execute("mutation { update(expectedVersion: 3) }").await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
}
