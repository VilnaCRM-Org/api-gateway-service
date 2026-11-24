//! Tests of the REST reads of session revocations and token cut-offs.

use std::sync::PoisonError;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use iam_domain::RevocationSource;
use serde_json::Value;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::http::{IamState, router};
use crate::revocation_read_fixtures::{
    Asked, OPERATOR_REVOCATION, OTHER_USER, Stored, UNKNOWN, USER_SERVICE_REVOCATION, asked_count,
    operator, scenario, stored,
};

fn app_over(data: Stored, failure: Option<fn() -> IamError>) -> (Router, Asked) {
    let (state, asked) = scenario(data, failure);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn app(failure: Option<fn() -> IamError>) -> (Router, Asked) {
    app_over(stored(), failure)
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
async fn an_operator_revocation_is_read_with_its_source_actor_session_user_and_time() {
    let (app, asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/session-revocations/{OPERATOR_REVOCATION}"), true),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], OPERATOR_REVOCATION);
    assert_eq!(body["sessionId"], "session-1");
    assert_eq!(body["userId"], USER);
    assert_eq!(body["source"], "operator");
    assert_eq!(body["actor"], operator().to_string());
    assert!(body["revokedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .gets
            .len(),
        1
    );
}

#[tokio::test]
async fn a_user_service_revocation_is_read_with_the_user_service_actor() {
    let (app, _asked) = app(None);

    let (status, body) = answer(
        app,
        get(
            &format!("/session-revocations/{USER_SERVICE_REVOCATION}"),
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source"], "user-service");
    assert_eq!(body["actor"], "system:user-service");
}

#[tokio::test]
async fn an_unknown_revocation_is_a_404_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get(&format!("/session-revocations/{UNKNOWN}"), true)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/session-revocations/nope", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "id");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_revocations_are_listed_newest_first() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/session-revocations", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], USER_SERVICE_REVOCATION);
    assert_eq!(body["items"][1]["id"], OPERATOR_REVOCATION);
    assert!(body.get("nextCursor").is_none());
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 30);
}

#[tokio::test]
async fn a_page_of_one_names_the_cursor_and_the_cursor_continues_after_it() {
    let (first_app, _asked) = app(None);
    let (second_app, _other) = app(None);

    let (first_status, first) = answer(first_app, get("/session-revocations?limit=1", true)).await;
    let (second_status, second) = answer(
        second_app,
        get(
            &format!("/session-revocations?limit=1&after={USER_SERVICE_REVOCATION}"),
            true,
        ),
    )
    .await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["nextCursor"], USER_SERVICE_REVOCATION);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second["items"][0]["id"], OPERATOR_REVOCATION);
}

#[tokio::test]
async fn the_filters_reach_the_query() {
    let (app, asked) = app(None);

    let (status, _body) = answer(
        app,
        get(
            &format!(
                "/session-revocations?userId={USER}&source=operator&from=2026-11-23T08:00:00Z&until=2026-11-23T09:00:00Z"
            ),
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    let query = &recorded.lists[0];
    assert_eq!(
        query.user.map(|user| user.to_string()),
        Some(USER.to_owned())
    );
    assert_eq!(query.source, Some(RevocationSource::Operator));
    assert!(query.from.is_some() && query.until.is_some());
    drop(recorded);
}

#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_without_a_query() {
    let (limit_app, asked) = app(None);
    let (source_app, _other) = app(None);

    let (limit_status, _limit) = answer(limit_app, get("/session-revocations?limit=0", true)).await;
    let (source_status, body) =
        answer(source_app, get("/session-revocations?source=maybe", true)).await;

    assert_eq!(limit_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(source_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "source");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_cutoff_of_a_user_is_read_with_its_instant_source_and_actor() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get(&format!("/users/{USER}/token-cutoff"), true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["userId"], USER);
    assert_eq!(body["source"], "operator");
    assert_eq!(body["actor"], operator().to_string());
    assert!(body["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .users
            .len(),
        1
    );
}

#[tokio::test]
async fn a_user_without_a_cutoff_is_a_404_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get(&format!("/users/{OTHER_USER}/token-cutoff"), true)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn a_user_id_that_is_not_a_uuid_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/users/nope/token-cutoff", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "userId");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_global_cutoff_is_read_with_its_instant_source_and_actor() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/global-token-cutoffs/current", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source"], "operator");
    assert_eq!(body["actor"], operator().to_string());
    assert!(body["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert!(body["setAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked.lock().unwrap_or_else(PoisonError::into_inner).globals,
        1
    );
}

#[tokio::test]
async fn a_global_cutoff_that_was_never_set_is_a_404_problem() {
    let (app, _asked) = app_over(Stored::default(), None);

    let (status, body) = answer(app, get("/global-token-cutoffs/current", true)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn a_request_without_a_principal_is_a_401_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, _body) = answer(app, get("/global-token-cutoffs/current", false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_storage_failure_is_a_500_problem_on_every_read() {
    for uri in [
        "/session-revocations".to_owned(),
        format!("/session-revocations/{OPERATOR_REVOCATION}"),
        format!("/users/{USER}/token-cutoff"),
        "/global-token-cutoffs/current".to_owned(),
    ] {
        let (app, _asked) = app(Some(|| IamError::Storage("down".into())));

        let (status, _body) = answer(app, get(&uri, true)).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
    }
}
