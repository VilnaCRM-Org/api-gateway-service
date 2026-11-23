use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{ActorRef, RequestDigester as _, RoleId};
use serde_json::{Value, json};
use shared_domain::Uuid;
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::command::set_role_permissions::SetRolePermissionsCommand;
use crate::error::IamError;
use crate::fixtures::{ROLE, USER, principal, receipt_at};
use crate::http::role_permission::dto::SetRolePermissionsRequest;
use crate::http::{IamState, router};
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::role_permission_fixtures::{Answers, Log, recorded, scenario};

type World = (
    Router,
    Arc<FakeCommandBus>,
    Arc<FakeQueryBus>,
    Log<SetRolePermissionsCommand>,
    Log<GetIdempotentReplayQuery>,
);

fn app(answers: Answers) -> World {
    let (state, commands, queries, sent, replays) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), commands, queries, sent, replays)
}

fn request(method: Method, headers: &[(&str, &str)], body: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/roles/{ROLE}/permissions"));
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

fn put(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(Method::PUT, headers, Some(body))
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

fn permissions_json(version: i64) -> Value {
    json!({
        "roleId": ROLE,
        "version": version,
        "permissions": [
            {
                "key": "gql:billing:*",
                "kind": "gql",
                "service": "billing",
                "active": true,
                "wildcard": true
            },
            {
                "key": "rest:billing:GET /invoices",
                "kind": "rest",
                "service": "billing",
                "active": false,
                "wildcard": false
            }
        ]
    })
}

#[tokio::test]
async fn the_grants_of_a_role_are_listed_with_the_etag_of_its_version() {
    let (app, _commands, queries, ..) = app(Answers::default());

    let (status, headers, body) = answer(app, request(Method::GET, &[], None)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(body, permissions_json(2));
    assert_eq!(queries.asked(), ["GetRolePermissionsQuery"]);
}

#[tokio::test]
async fn an_unknown_role_has_no_grants_to_list() {
    let (app, ..) = app(Answers {
        permissions: Ok(None),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(app, request(Method::GET, &[], None)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn a_failing_read_of_the_grants_is_a_server_error() {
    let (app, ..) = app(Answers {
        permissions: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(app, request(Method::GET, &[], None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_role_id_that_is_not_a_uuid_is_a_validation_failure() {
    let (state, ..) = scenario(Answers::default());
    let (routes, _document) = router::<IamState>().split_for_parts();
    let mut bad = Request::builder()
        .method(Method::GET)
        .uri("/roles/not-a-uuid/permissions")
        .body(Body::empty())
        .unwrap();
    bad.extensions_mut().insert(principal());

    let (status, ..) = answer(routes.with_state(state), bad).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_replacement_returns_the_grants_with_the_new_etag_and_the_policy_version() {
    let (app, commands, queries, sent, _replays) = app(Answers::default());

    let (status, headers, body) = answer(
        app,
        put(
            &[("if-match", "\"1\"")],
            r#"{"keys":["gql:billing:*","rest:billing:GET /invoices"]}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("9".to_owned()));
    assert_eq!(body, permissions_json(2));
    assert_eq!(commands.dispatched(), ["SetRolePermissionsCommand"]);
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetRolePermissionsQuery"]
    );
    let dispatched = recorded(&sent);
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(
        dispatched[0].actor,
        ActorRef::User(Uuid::parse(USER).unwrap())
    );
    assert_eq!(dispatched[0].expected.value(), 1);
    assert_eq!(
        dispatched[0].keys,
        ["gql:billing:*", "rest:billing:GET /invoices"]
    );
    assert_eq!(dispatched[0].idempotency, None);
}

#[tokio::test]
async fn the_idempotency_key_and_the_digest_of_the_request_reach_the_command() {
    let (app, _commands, _queries, sent, replays) = app(Answers::default());

    let (status, ..) = answer(
        app,
        put(
            &[("if-match", "\"1\""), ("idempotency-key", "grants-1")],
            r#"{"keys":["gql:billing:*"]}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let idempotency = recorded(&sent)[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "grants-1");
    let expected = FakeRequestDigester.digest(
        &SetRolePermissionsRequest {
            keys: vec!["gql:billing:*".to_owned()],
        }
        .canonical_form(
            RoleId::parse(ROLE).unwrap(),
            iam_domain::EntityVersion::new(1).unwrap(),
        ),
    );
    assert_eq!(idempotency.request_digest, expected);
    assert_eq!(recorded(&replays).len(), 1);
}

#[tokio::test]
async fn a_replayed_replacement_returns_the_original_receipt_without_a_command() {
    let (app, commands, _queries, ..) = app(Answers {
        replay: Ok(Some(receipt_at(2, Some(4)))),
        ..Answers::default()
    });

    let (status, headers, _body) = answer(
        app,
        put(
            &[("if-match", "\"1\""), ("idempotency-key", "grants-1")],
            r#"{"keys":[]}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "iam-policy-version"), Some("4".to_owned()));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_lookup_of_the_idempotent_replay_is_a_server_error_without_a_command() {
    let (app, commands, ..) = app(Answers {
        replay: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(
        app,
        put(
            &[("if-match", "\"1\""), ("idempotency-key", "grants-1")],
            r#"{"keys":[]}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replacement_without_if_match_is_428_and_a_stale_one_is_412() {
    let (app_without, ..) = app(Answers::default());
    let (stale, ..) = app(Answers {
        command: Err(|| IamError::PreconditionFailed),
        ..Answers::default()
    });

    let (missing, ..) = answer(app_without, put(&[], r#"{"keys":[]}"#)).await;
    let (refused, ..) = answer(stale, put(&[("if-match", "\"1\"")], r#"{"keys":[]}"#)).await;

    assert_eq!(missing, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(refused, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn unknown_keys_are_one_violation_each_in_a_422() {
    let (app, ..) = app(Answers {
        command: Err(|| {
            IamError::Invalid(vec![
                shared_application::http::Violation {
                    property_path: "keys[0]".to_owned(),
                    message: "unknown".to_owned(),
                    code: "exists".to_owned(),
                },
                shared_application::http::Violation {
                    property_path: "keys[2]".to_owned(),
                    message: "unknown".to_owned(),
                    code: "exists".to_owned(),
                },
            ])
        }),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(
        app,
        put(&[("if-match", "\"1\"")], r#"{"keys":["a","b","c"]}"#),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let paths: Vec<&str> = body["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|violation| violation["propertyPath"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["keys[0]", "keys[2]"]);
}

#[tokio::test]
async fn more_than_five_thousand_keys_are_refused_before_any_command() {
    let (app, commands, ..) = app(Answers::default());
    let keys: Vec<String> = (0..=5_000)
        .map(|n| format!("rest:billing:GET /a{n}"))
        .collect();
    let body = json!({ "keys": keys }).to_string();

    let (status, _headers, body) = answer(app, put(&[("if-match", "\"1\"")], &body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "keys");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replacement_of_an_unknown_role_is_404() {
    let (app, ..) = app(Answers {
        command: Err(|| IamError::NotFound),
        ..Answers::default()
    });

    let (status, ..) = answer(app, put(&[("if-match", "\"1\"")], r#"{"keys":[]}"#)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_role_that_vanishes_after_the_commit_is_404() {
    let (app, ..) = app(Answers {
        permissions: Ok(None),
        ..Answers::default()
    });

    let (status, ..) = answer(app, put(&[("if-match", "\"1\"")], r#"{"keys":[]}"#)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn both_operations_need_a_caller() {
    let (app_get, ..) = app(Answers::default());
    let (app_put, ..) = app(Answers::default());
    let mut get = request(Method::GET, &[], None);
    get.extensions_mut().remove::<crate::principal::Principal>();
    let mut replace = put(&[("if-match", "\"1\"")], r#"{"keys":[]}"#);
    replace
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (read, ..) = answer(app_get, get).await;
    let (write, ..) = answer(app_put, replace).await;

    assert_eq!(read, StatusCode::UNAUTHORIZED);
    assert_eq!(write, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_body_above_the_limit_of_the_route_is_413_and_a_body_below_it_is_read() {
    let (app_large, commands, ..) = app(Answers::default());
    let (app_small, ..) = app(Answers::default());
    let limit = super::ROLE_PERMISSIONS_BODY_LIMIT_BYTES;
    let too_large = format!(r#"{{"keys":["{}"]}}"#, "k".repeat(limit));
    let large_enough = format!(r#"{{"keys":["{}"]}}"#, "k".repeat(limit / 2));

    let (refused, ..) = answer(app_large, put(&[("if-match", "\"1\"")], &too_large)).await;
    let (read, ..) = answer(app_small, put(&[("if-match", "\"1\"")], &large_enough)).await;

    assert_eq!(refused, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(read, StatusCode::OK);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}
