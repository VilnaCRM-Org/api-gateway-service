use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{EntityVersion, HttpMethod, PropagationOutcome};
use rstest::rstest;
use serde_json::{Value, json};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::command::update_route::CorsChange;
use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};
use crate::query::list_routes::{ListRoutesQuery, RoutePage};
use crate::route_fixtures::{
    Answers, Asked, ROUTE, UPSTREAM, actor, receipt, receipt_at, recorded, route, route_id,
    scenario, upstream_id,
};

/// The router over the doubles, with the doubles to read back.
fn app(answers: Answers) -> (Router, Arc<FakeCommandBus>, Arc<FakeQueryBus>, Asked) {
    let (state, commands, queries, asked) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), commands, queries, asked)
}

/// A request of a caller whose token the middleware resolved.
fn request(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let mut request = builder
        .body(Body::from(body.unwrap_or_default().to_owned()))
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

fn anonymous(mut request: Request<Body>) -> Request<Body> {
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();
    request
}

fn post(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(Method::POST, "/routes", headers, Some(body))
}

fn get(uri: &str) -> Request<Body> {
    request(Method::GET, uri, &[], None)
}

fn one() -> String {
    format!("/routes/{ROUTE}")
}

fn patch(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(Method::PATCH, &one(), headers, Some(body))
}

fn delete(headers: &[(&str, &str)]) -> Request<Body> {
    request(Method::DELETE, &one(), headers, None)
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

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

fn create_body() -> String {
    format!(
        r#"{{"host":"app.example.test","methods":["GET"],"pathPattern":"/api/orders/{{id}}","service":"core","upstreamId":"{UPSTREAM}"}}"#
    )
}

fn route_json(version: i64) -> Value {
    json!({
        "id": ROUTE,
        "host": "app.example.test",
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": false,
        "streaming": false,
        "anonymous": false,
        "enforcement": "enforce",
        "bodyLimitBytes": 1_048_576,
        "requestTimeoutMs": 30_000,
        "idleTimeoutMs": 60_000,
        "retryPolicy": "none",
        "ratePolicyIds": [],
        "system": false,
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:05:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_route_is_201_with_its_location_etag_policy_version_and_data() {
    let answers = Answers {
        receipt: receipt(Some(7)),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, body) = answer(app, post(&[], &create_body())).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/routes/{ROUTE}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, route_json(1));
    assert_eq!(commands.dispatched(), ["CreateRouteCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery", "GetRouteQuery"]);
    assert_eq!(recorded(&asked.routes), [route_id()]);
}

#[tokio::test]
async fn the_command_carries_the_caller_the_fields_and_fresh_identifiers() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(app, post(&[], &create_body())).await;

    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].draft.host, "app.example.test");
    assert_eq!(sent[0].draft.methods, [HttpMethod::Get]);
    assert_eq!(sent[0].draft.upstream_id, upstream_id());
    assert_eq!(sent[0].idempotency, None);
    assert_ne!(sent[0].change_id.as_uuid(), sent[0].route_id.as_uuid());
}

#[tokio::test]
async fn a_receipt_that_was_not_acknowledged_in_time_is_202_with_its_status() {
    let answers = Answers {
        receipt: receipt(Some(5)).with_propagation(PropagationOutcome::CommittedPending),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, headers, _body) = answer(app, post(&[], &create_body())).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        header(&headers, "iam-propagation-status"),
        Some("committed_pending_propagation".to_owned())
    );
}

#[tokio::test]
async fn waiting_for_the_propagated_mode_is_the_422_problem_naming_the_mode() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) =
        answer(app, post(&[("prefer", "wait=propagated")], &create_body())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("prefer"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_creation_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, anonymous(post(&[], &create_body()))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::empty_host(
    r#"{"host":"","methods":["GET"],"pathPattern":"/a","service":"core","upstreamId":"x"}"#,
    "host"
)]
#[case::empty_path(
    r#"{"host":"h","methods":["GET"],"pathPattern":"","service":"core","upstreamId":"x"}"#,
    "pathPattern"
)]
#[case::empty_service(
    r#"{"host":"h","methods":["GET"],"pathPattern":"/a","service":"","upstreamId":"x"}"#,
    "service"
)]
#[tokio::test]
async fn an_invalid_field_is_a_422_problem_naming_it_and_dispatches_nothing(
    #[case] body: &str,
    #[case] property: &str,
) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, post(&[], body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_upstream_id_that_is_not_a_uuid_is_a_422_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());
    let body = r#"{"host":"h.example.test","methods":["GET"],"pathPattern":"/a","service":"core","upstreamId":"nope"}"#;

    let (status, _headers, problem) = answer(app, post(&[], body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["violations"][0]["propertyPath"],
        json!("upstreamId")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::missing_methods(r#"{"host":"h","pathPattern":"/a","service":"core","upstreamId":"x"}"#)]
#[case::unknown_method(
    r#"{"host":"h","methods":["TRACE"],"pathPattern":"/a","service":"core","upstreamId":"x"}"#
)]
#[case::unknown_member(r#"{"host":"h","methods":["GET"],"pathPattern":"/a","service":"core","upstreamId":"x","system":true}"#)]
#[case::not_json("host=a")]
#[tokio::test]
async fn a_malformed_body_is_a_client_error_and_dispatches_nothing(#[case] body: &str) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, post(&[], body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::conflict(|| IamError::RouteTableConflict { code: "same_pattern" }, StatusCode::CONFLICT)]
#[case::system_entry(|| IamError::SystemEntry, StatusCode::CONFLICT)]
#[case::forbidden(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[case::invalid(
    || IamError::from(vec![iam_domain::InvalidRoute::HostFormat]),
    StatusCode::UNPROCESSABLE_ENTITY
)]
#[tokio::test]
async fn a_refusal_of_the_command_is_its_problem_and_reads_nothing_back(
    #[case] refusal: fn() -> IamError,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        command: Err(refusal),
        ..Answers::default()
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], &create_body())).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_route_table_conflict_problem_has_its_own_type() {
    let answers = Answers {
        command: Err(|| IamError::RouteTableConflict {
            code: "same_pattern",
        }),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (_status, _headers, problem) = answer(app, post(&[], &create_body())).await;

    assert_eq!(problem["type"], json!("/problems/route-table-conflict"));
}

#[tokio::test]
async fn a_new_idempotency_key_creates_the_route_and_travels_with_the_command() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, _headers, _body) = answer(
        app,
        post(&[("Idempotency-Key", "create-route")], &create_body()),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetRouteQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays[0].request.key.as_str(), "create-route");
    assert_eq!(
        recorded(&asked.commands)[0].idempotency,
        Some(replays[0].request.clone())
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt(Some(3)))),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        post(&[("Idempotency-Key", "create-route")], &create_body()),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header(&headers, "iam-policy-version"), Some("3".to_owned()));
    assert_eq!(body, route_json(1));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetRouteQuery"]
    );
}

#[tokio::test]
async fn a_route_is_read_with_the_etag_of_its_version() {
    let answers = Answers {
        route: Ok(Some(route(4))),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, headers, body) = answer(app, get(&one())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"4\"".to_owned()));
    assert_eq!(body, route_json(4));
}

#[tokio::test]
async fn an_unknown_route_is_the_404_problem() {
    let answers = Answers {
        route: Ok(None),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, _headers, body) = answer(app, get(&one())).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], json!(404));
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_a_422_problem_naming_the_id() {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, get("/routes/not-a-uuid")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem() {
    let (app, ..) = app(Answers::default());

    let (status, ..) = answer(app, anonymous(get(&one()))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_page_of_routes_lists_its_items_its_cursor_and_the_filters_reach_the_query() {
    let answers = Answers {
        page: Ok(RoutePage {
            routes: vec![route(1)],
            next_after: Some(route_id()),
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);
    let uri = format!(
        "/routes?limit=1&after={ROUTE}&host=app.example.test&upstream={UPSTREAM}&service=core"
    );

    let (status, _headers, body) = answer(app, get(&uri)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "items": [route_json(1)], "nextCursor": ROUTE })
    );
    let asked = recorded(&asked.lists);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].limit, 1);
    assert_eq!(asked[0].after, Some(route_id()));
    assert_eq!(asked[0].host.as_ref().unwrap().as_str(), "app.example.test");
    assert_eq!(asked[0].upstream, Some(upstream_id()));
    assert_eq!(asked[0].service.as_ref().unwrap().as_str(), "core");
}

#[tokio::test]
async fn the_last_page_has_no_cursor_and_the_default_size_is_30() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, get("/routes")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "items": [] }));
    assert_eq!(
        recorded(&asked.lists),
        [ListRoutesQuery {
            limit: 30,
            after: None,
            host: None,
            upstream: None,
            service: None,
        }]
    );
}

#[rstest]
#[case::zero("/routes?limit=0", "limit")]
#[case::above_the_maximum("/routes?limit=101", "limit")]
#[case::cursor("/routes?after=nope", "after")]
#[case::host("/routes?host=Bad%20Host", "host")]
#[case::upstream("/routes?upstream=nope", "upstream")]
#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_naming_it(
    #[case] uri: &str,
    #[case] property: &str,
) {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!(property));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_update_is_200_with_the_new_version_and_the_policy_version() {
    let answers = Answers {
        receipt: receipt_at(2, Some(8)),
        route: Ok(Some(route(2))),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        patch(
            &[("If-Match", "\"1\"")],
            r#"{"requestTimeoutMs":5000,"cors":null}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("8".to_owned()));
    assert_eq!(body, route_json(2));
    assert_eq!(commands.dispatched(), ["UpdateRouteCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery", "GetRouteQuery"]);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].route_id, route_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].patch.request_timeout_ms, Some(5000));
    assert_eq!(sent[0].patch.cors, CorsChange::Remove);
    assert_eq!(sent[0].patch.host, None);
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, patch(&[], r#"{"streaming":true}"#)).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["status"], json!(428));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[case::system_entry(|| IamError::SystemEntry, StatusCode::CONFLICT)]
#[case::forbidden(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[tokio::test]
async fn a_refusal_of_the_update_is_its_problem(
    #[case] refusal: fn() -> IamError,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        update: Err(refusal),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, ..) = answer(
        app,
        patch(&[("If-Match", "\"1\"")], r#"{"streaming":true}"#),
    )
    .await;

    assert_eq!(status, expected);
}

#[tokio::test]
async fn an_update_with_a_replayed_key_returns_the_stored_route_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(4)))),
        route: Ok(Some(route(2))),
        ..Answers::default()
    };
    let (app, commands, ..) = app(answers);

    let (status, ..) = answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "update-route")],
            r#"{"streaming":true}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_route_deleted_meanwhile_is_a_404_after_an_update() {
    let answers = Answers {
        route: Ok(None),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, ..) = answer(
        app,
        patch(&[("If-Match", "\"1\"")], r#"{"streaming":true}"#),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_deletion_is_204_with_the_final_version_and_the_policy_version() {
    let answers = Answers {
        receipt: receipt_at(2, Some(9)),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, _body) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("9".to_owned()));
    assert_eq!(commands.dispatched(), ["DeleteRouteCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent[0].route_id, route_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
}

#[tokio::test]
async fn a_deletion_without_if_match_is_the_428_problem() {
    let (app, commands, ..) = app(Answers::default());

    let (status, ..) = answer(app, delete(&[])).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_refused_deletion_is_its_problem() {
    let answers = Answers {
        delete: Err(|| IamError::SystemEntry),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, _headers, body) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["type"], json!("/problems/system-entry"));
}

#[tokio::test]
async fn a_deletion_with_a_replayed_key_returns_the_original_receipt_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(6)))),
        ..Answers::default()
    };
    let (app, commands, ..) = app(answers);

    let (status, headers, _body) = answer(
        app,
        delete(&[("If-Match", "\"1\""), ("Idempotency-Key", "delete-route")]),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header(&headers, "iam-policy-version"), Some("6".to_owned()));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}
