use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{ActorRef, EntityVersion, PropagationOutcome, UpstreamProtocol};
use rstest::rstest;
use serde_json::{Value, json};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::http::{IamState, router};
use crate::query::list_upstreams::{ListUpstreamsQuery, UpstreamPage};
use crate::upstream_fixtures::{
    Answers, Asked, UPSTREAM, actor, receipt, receipt_at, recorded, scenario, upstream, upstream_id,
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
    request(Method::POST, "/upstreams", headers, Some(body))
}

fn get(uri: &str) -> Request<Body> {
    request(Method::GET, uri, &[], None)
}

fn one() -> String {
    format!("/upstreams/{UPSTREAM}")
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

const CREATE_BODY: &str = r#"{"name":"core","namespace":"platform","service":"core-service","catalogService":"core","port":8080,"protocol":"h2c"}"#;

fn upstream_json(version: i64) -> Value {
    json!({
        "id": UPSTREAM,
        "name": "core",
        "namespace": "platform",
        "service": "core-service",
        "catalogService": "core",
        "forwardCredentials": false,
        "port": 8080,
        "protocol": "h2c",
        "connectTimeoutMs": 250,
        "responseTimeoutMs": 10_000,
        "concurrencyLimit": 256,
        "retryBudgetPercent": 10,
        "outlierConsecutiveErrors": 5,
        "system": false,
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:05:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_upstream_is_201_with_its_location_etag_policy_version_and_data() {
    let answers = Answers {
        receipt: receipt(Some(7)),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, body) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/upstreams/{UPSTREAM}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, upstream_json(1));
    assert_eq!(commands.dispatched(), ["CreateUpstreamCommand"]);
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetUpstreamQuery"]
    );
    assert_eq!(recorded(&asked.upstreams), [upstream_id()]);
}

#[tokio::test]
async fn the_command_carries_the_caller_the_fields_and_fresh_identifiers() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(app, post(&[], CREATE_BODY)).await;

    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].name, "core");
    assert_eq!(sent[0].settings.namespace, "platform");
    assert_eq!(sent[0].settings.service_name, "core-service");
    assert_eq!(sent[0].settings.catalog_service, "core");
    assert_eq!(sent[0].settings.port, 8080);
    assert_eq!(sent[0].settings.protocol, UpstreamProtocol::H2c);
    assert!(!sent[0].settings.forward_credentials);
    assert_eq!(sent[0].idempotency, None);
    assert_ne!(sent[0].change_id.as_uuid(), sent[0].upstream_id.as_uuid());
}

#[tokio::test]
async fn the_members_that_the_body_leaves_out_take_their_defaults() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(app, post(&[], CREATE_BODY)).await;

    let settings = &recorded(&asked.commands)[0].settings;
    assert_eq!(settings.connect_timeout_ms, 250);
    assert_eq!(settings.response_timeout_ms, 10_000);
    assert_eq!(settings.concurrency_limit, 256);
    assert_eq!(settings.retry_budget_percent, 10);
    assert_eq!(settings.outlier_threshold, 5);
}

#[tokio::test]
async fn every_member_of_the_body_reaches_the_command() {
    let (app, _commands, _queries, asked) = app(Answers::default());
    let body = r#"{"name":"core","namespace":"platform","service":"core-service","catalogService":"core","forwardCredentials":true,"port":9090,"protocol":"http1","connectTimeoutMs":500,"responseTimeoutMs":20000,"concurrencyLimit":64,"retryBudgetPercent":25,"outlierConsecutiveErrors":3}"#;

    answer(app, post(&[], body)).await;

    let settings = &recorded(&asked.commands)[0].settings;
    assert!(settings.forward_credentials);
    assert_eq!(settings.port, 9090);
    assert_eq!(settings.protocol, UpstreamProtocol::Http1);
    assert_eq!(settings.connect_timeout_ms, 500);
    assert_eq!(settings.response_timeout_ms, 20_000);
    assert_eq!(settings.concurrency_limit, 64);
    assert_eq!(settings.retry_budget_percent, 25);
    assert_eq!(settings.outlier_threshold, 3);
}

#[tokio::test]
async fn a_receipt_that_was_not_acknowledged_in_time_is_202_with_its_status() {
    let answers = Answers {
        receipt: receipt(Some(5)).with_propagation(PropagationOutcome::CommittedPending),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, headers, _body) = answer(app, post(&[], CREATE_BODY)).await;

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
        answer(app, post(&[("prefer", "wait=propagated")], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("prefer"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_creation_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, anonymous(post(&[], CREATE_BODY))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::empty_name(
    r#"{"name":"","namespace":"p","service":"s","catalogService":"c","port":1,"protocol":"http1"}"#,
    "name"
)]
#[case::empty_namespace(
    r#"{"name":"n","namespace":"","service":"s","catalogService":"c","port":1,"protocol":"http1"}"#,
    "namespace"
)]
#[case::long_service(&format!(r#"{{"name":"n","namespace":"p","service":"{}","catalogService":"c","port":1,"protocol":"http1"}}"#, "s".repeat(64)), "service")]
#[case::empty_catalog_service(
    r#"{"name":"n","namespace":"p","service":"s","catalogService":"","port":1,"protocol":"http1"}"#,
    "catalogService"
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
    assert_eq!(problem["violations"][0]["code"], json!("length"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::missing_port(
    r#"{"name":"n","namespace":"p","service":"s","catalogService":"c","protocol":"http1"}"#
)]
#[case::unknown_protocol(
    r#"{"name":"n","namespace":"p","service":"s","catalogService":"c","port":1,"protocol":"quic"}"#
)]
#[case::unknown_member(r#"{"name":"n","namespace":"p","service":"s","catalogService":"c","port":1,"protocol":"http1","system":true}"#)]
#[case::not_json("name=a")]
#[tokio::test]
async fn a_malformed_body_is_a_client_error_and_dispatches_nothing(#[case] body: &str) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, post(&[], body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::duplicate(|| IamError::Conflict, StatusCode::CONFLICT)]
#[case::system_entry(|| IamError::SystemEntry, StatusCode::CONFLICT)]
#[case::forbidden(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[case::invalid(
    || IamError::from(vec![iam_domain::InvalidUpstream::PortRange]),
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

    let (status, _headers, problem) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_system_entry_problem_has_its_own_type() {
    let answers = Answers {
        command: Err(|| IamError::SystemEntry),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (_status, _headers, problem) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(problem["type"], json!("/problems/system-entry"));
}

#[tokio::test]
async fn a_new_idempotency_key_creates_the_upstream_and_travels_with_the_command() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, _headers, _body) = answer(
        app,
        post(&[("Idempotency-Key", "create-core")], CREATE_BODY),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetUpstreamQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays.len(), 1);
    assert_eq!(
        replays[0].actor,
        ActorRef::User(shared_domain::Uuid::parse(USER).unwrap())
    );
    assert_eq!(replays[0].request.key.as_str(), "create-core");
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].idempotency, Some(replays[0].request.clone()));
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
        post(&[("Idempotency-Key", "create-core")], CREATE_BODY),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header(&headers, "iam-policy-version"), Some("3".to_owned()));
    assert_eq!(body, upstream_json(1));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetUpstreamQuery"]
    );
}

#[tokio::test]
async fn the_same_key_with_another_body_has_another_digest() {
    let (first, _c1, _q1, asked_first) = app(Answers::default());
    let (second, _c2, _q2, asked_second) = app(Answers::default());
    let key = [("Idempotency-Key", "create-core")];
    let other = CREATE_BODY.replace("8080", "8081");

    answer(first, post(&key, CREATE_BODY)).await;
    answer(second, post(&key, &other)).await;

    assert_ne!(
        recorded(&asked_first.replays)[0].request.request_digest,
        recorded(&asked_second.replays)[0].request.request_digest
    );
}

#[tokio::test]
async fn an_upstream_is_read_with_the_etag_of_its_version() {
    let answers = Answers {
        upstream: Ok(Some(upstream(4))),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, headers, body) = answer(app, get(&one())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"4\"".to_owned()));
    assert_eq!(body, upstream_json(4));
}

#[tokio::test]
async fn an_unknown_upstream_is_the_404_problem() {
    let answers = Answers {
        upstream: Ok(None),
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

    let (status, _headers, body) = answer(app, get("/upstreams/not-a-uuid")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(body["violations"][0]["code"], json!("uuid"));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem() {
    let (app, ..) = app(Answers::default());

    let (status, ..) = answer(app, anonymous(get(&one()))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_page_of_upstreams_lists_its_items_and_its_cursor() {
    let answers = Answers {
        page: Ok(UpstreamPage {
            upstreams: vec![upstream(1)],
            next_after: Some(upstream_id()),
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);

    let (status, _headers, body) =
        answer(app, get(&format!("/upstreams?limit=1&after={UPSTREAM}"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "items": [upstream_json(1)], "nextCursor": UPSTREAM })
    );
    assert_eq!(
        recorded(&asked.lists),
        [ListUpstreamsQuery {
            limit: 1,
            after: Some(upstream_id())
        }]
    );
}

#[tokio::test]
async fn the_last_page_has_no_cursor_and_the_default_size_is_30() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, get("/upstreams")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "items": [] }));
    assert_eq!(
        recorded(&asked.lists),
        [ListUpstreamsQuery {
            limit: 30,
            after: None
        }]
    );
}

#[rstest]
#[case::zero("/upstreams?limit=0", "limit")]
#[case::above_the_maximum("/upstreams?limit=101", "limit")]
#[case::cursor("/upstreams?after=nope", "after")]
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
        upstream: Ok(Some(upstream(2))),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        patch(
            &[("If-Match", "\"1\"")],
            r#"{"port":9090,"protocol":"http1"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("8".to_owned()));
    assert_eq!(body, upstream_json(2));
    assert_eq!(commands.dispatched(), ["UpdateUpstreamCommand"]);
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetUpstreamQuery"]
    );
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].upstream_id, upstream_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].patch.port, Some(9090));
    assert_eq!(sent[0].patch.protocol, Some(UpstreamProtocol::Http1));
    assert_eq!(sent[0].patch.namespace, None);
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, patch(&[], r#"{"port":9090}"#)).await;

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
async fn a_refused_update_is_the_problem_of_its_cause(
    #[case] refusal: fn() -> IamError,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        update: Err(refusal),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, ..) = answer(app, patch(&[("If-Match", "\"1\"")], r#"{"port":9090}"#)).await;

    assert_eq!(status, expected);
}

#[tokio::test]
async fn an_update_that_names_an_unknown_member_is_a_client_error() {
    let (app, commands, ..) = app(Answers::default());

    let (status, ..) = answer(app, patch(&[("If-Match", "\"1\"")], r#"{"system":true}"#)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replayed_update_returns_the_original_result_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(8)))),
        upstream: Ok(Some(upstream(2))),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, headers, _body) = answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "update-core")],
            r#"{"port":9090}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_new_idempotency_key_updates_the_upstream_and_travels_with_the_command() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "update-core")],
            r#"{"port":9090}"#,
        ),
    )
    .await;

    let replays = recorded(&asked.replays);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].idempotency, Some(replays[0].request.clone()));
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
    assert_eq!(commands.dispatched(), ["DeleteUpstreamCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent[0].upstream_id, upstream_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
}

#[tokio::test]
async fn a_deletion_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, ..) = app(Answers::default());

    let (status, ..) = answer(app, delete(&[])).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::referenced(|| IamError::ReferencedByRoute, StatusCode::CONFLICT)]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[tokio::test]
async fn a_refused_deletion_is_the_problem_of_its_cause(
    #[case] refusal: fn() -> IamError,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        delete: Err(refusal),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, ..) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, expected);
}

#[tokio::test]
async fn a_referenced_upstream_problem_has_its_own_type() {
    let answers = Answers {
        delete: Err(|| IamError::ReferencedByRoute),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (_status, _headers, problem) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(problem["type"], json!("/problems/referenced-by-route"));
}

#[tokio::test]
async fn a_replayed_deletion_returns_the_original_receipt_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(9)))),
        ..Answers::default()
    };
    let (app, commands, ..) = app(answers);

    let (status, headers, _body) = answer(
        app,
        delete(&[("If-Match", "\"1\""), ("Idempotency-Key", "delete-core")]),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header(&headers, "iam-policy-version"), Some("9".to_owned()));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_new_idempotency_key_deletes_the_upstream_and_travels_with_the_command() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(
        app,
        delete(&[("If-Match", "\"1\""), ("Idempotency-Key", "delete-core")]),
    )
    .await;

    let replays = recorded(&asked.replays);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent[0].idempotency, Some(replays[0].request.clone()));
}

#[test]
fn the_router_documents_the_upstream_operations_under_the_iam_tag_behind_the_bearer_scheme() {
    let (_routes, document) = router::<IamState>().split_for_parts();

    let collection = &document.paths.paths["/upstreams"];
    let item = &document.paths.paths["/upstreams/{id}"];
    let operations = [
        (collection.post.as_ref().unwrap(), "api_upstreams_post"),
        (collection.get.as_ref().unwrap(), "api_upstreams_get"),
        (item.get.as_ref().unwrap(), "api_upstreams_id_get"),
        (item.patch.as_ref().unwrap(), "api_upstreams_id_patch"),
        (item.delete.as_ref().unwrap(), "api_upstreams_id_delete"),
    ];
    for (operation, operation_id) in operations {
        assert_eq!(operation.operation_id.as_deref(), Some(operation_id));
        assert_eq!(
            operation.tags.as_deref(),
            Some(["iam".to_owned()].as_slice())
        );
        assert!(operation.security.is_some(), "{operation_id}");
    }
    assert!(collection.put.is_none() && collection.delete.is_none() && collection.patch.is_none());
    assert!(item.post.is_none() && item.put.is_none());
}

#[tokio::test]
async fn a_key_reused_for_another_request_is_a_422_problem_and_dispatches_nothing() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(
        app,
        post(&[("Idempotency-Key", "create-core")], CREATE_BODY),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_read_is_the_500_problem() {
    let failing_read = Answers {
        upstream: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    };
    let failing_list = Answers {
        page: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    };
    let (read_app, _commands, _queries, _asked) = app(failing_read);
    let (list_app, _commands, _queries, _asked) = app(failing_list);

    let (read, _headers, _problem) = answer(read_app, get(&one())).await;
    let (list, _headers, _problem) = answer(list_app, get("/upstreams")).await;

    assert_eq!(read, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(list, StatusCode::INTERNAL_SERVER_ERROR);
}
