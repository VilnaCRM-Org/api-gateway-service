//! Tests of the REST reads of the access decisions.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::access_decision_fixtures::{decision_id, entry};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};
use crate::query::get_access_decision::GetAccessDecisionQuery;
use crate::query::get_access_decisions::{AccessDecisionPage, GetAccessDecisionsQuery};
use crate::security_audit_fixtures::actor;

/// What the bus was asked.
#[derive(Debug, Default)]
struct Asked {
    lists: Vec<GetAccessDecisionsQuery>,
    gets: Vec<GetAccessDecisionQuery>,
}

fn app(failure: Option<fn() -> IamError>) -> (Router, Arc<Mutex<Asked>>) {
    let asked: Arc<Mutex<Asked>> = Arc::default();
    let list_log = Arc::clone(&asked);
    let get_log = Arc::clone(&asked);
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: GetAccessDecisionsQuery| {
            list_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .lists
                .push(query);
            failure.map_or_else(
                || {
                    Ok(AccessDecisionPage {
                        entries: vec![entry(2, 2_000_000_000), entry(1, 1_000_000_000)],
                        next: Some("sealed-token".to_owned()),
                    })
                },
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: GetAccessDecisionQuery| {
            let id = query.id;
            get_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .gets
                .push(query);
            failure.map_or_else(
                || Ok((id == decision_id(1)).then(|| entry(1, 1_000_000_000))),
                |refuse| Err(refuse()),
            )
        }),
    );
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> = queries;
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
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

const RANGE: &str = "from=2026-11-23T08:00:00Z&until=2026-11-23T09:00:00Z";

#[tokio::test]
async fn the_decisions_are_listed_newest_first_with_the_cursor_of_the_next_page() {
    let (app, asked) = app(None);

    let (status, body) = answer(
        app,
        get(
            &format!("/access-decisions?{RANGE}&decision=deny&status=403&limit=2"),
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], decision_id(2).to_string());
    assert_eq!(body["items"][1]["id"], decision_id(1).to_string());
    assert_eq!(body["items"][0]["decision"], "deny");
    assert_eq!(body["nextCursor"], "sealed-token");
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 2);
    assert_eq!(recorded.lists[0].actor, actor());
    assert_eq!(recorded.lists[0].filter.status, Some(403));
}

#[tokio::test]
async fn a_search_without_a_range_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/access-decisions", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "from");
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lists
            .len(),
        0
    );
}

#[tokio::test]
async fn a_page_size_above_the_maximum_is_a_422_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/access-decisions?{RANGE}&limit=501"), true),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "limit");
}

#[tokio::test]
async fn a_decision_is_read_by_id() {
    let (app, asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/access-decisions/{}", decision_id(1)), true),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], decision_id(1).to_string());
    assert_eq!(body["reason"], "permission_missing");
    assert!(body.get("credentialDigestPrefix").is_none());
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.gets[0].actor, actor());
}

#[tokio::test]
async fn an_unknown_decision_is_a_404_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/access-decisions/{}", decision_id(9)), true),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/access-decisions/nope", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "id");
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .gets
            .len(),
        0
    );
}

#[tokio::test]
async fn a_search_that_times_out_is_a_504_problem() {
    let (app, _asked) = app(Some(|| IamError::AccessLogTimeout));

    let (status, body) = answer(app, get(&format!("/access-decisions?{RANGE}"), true)).await;

    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body["status"], 504);
}

#[tokio::test]
async fn a_log_store_that_is_unavailable_is_a_503_problem() {
    let (app, _asked) = app(Some(|| IamError::AccessLogUnavailable));

    let (status, body) = answer(
        app,
        get(&format!("/access-decisions/{}", decision_id(1)), true),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], 503);
}

#[tokio::test]
async fn a_request_without_a_principal_is_a_401_problem() {
    let (app, _asked) = app(None);

    let (status, _body) = answer(app, get(&format!("/access-decisions?{RANGE}"), false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
