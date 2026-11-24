use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{ActorRef, PropagationOutcome, RateFallback, RateKeyKind, RatePolicyId};
use rstest::rstest;
use serde_json::{Value, json};
use shared_application::http::Violation;
use shared_domain::Uuid;
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{USER, principal, recorded};
use crate::http::{IamState, router};
use crate::query::list_rate_policies::RatePolicyPage;
use crate::rate_policy_fixtures::{
    Answers, Asked, POLICY, rate_policy, receipt, receipt_at, scenario,
};

const CREATE_BODY: &str = r#"{"name":"per-subject","key":"subject_route","limit":100,"periodMs":60000,"burst":20,"fallback":"divided"}"#;

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

fn post(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(Method::POST, "/rate-policies", headers, Some(body))
}

fn get(uri: &str) -> Request<Body> {
    request(Method::GET, uri, &[], None)
}

fn item(id: &str) -> String {
    format!("/rate-policies/{id}")
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

fn policy_json(version: i64) -> Value {
    json!({
        "id": POLICY,
        "name": "per-subject",
        "key": "subject_route",
        "limit": 100,
        "periodMs": 60_000,
        "burst": 20,
        "fallback": "divided",
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:01:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_policy_is_201_with_its_location_etag_policy_version_and_data() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, headers, body) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/rate-policies/{POLICY}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("1".to_owned()));
    assert_eq!(body, policy_json(1));
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetRatePolicyQuery"]
    );
    assert_eq!(
        recorded(&asked.rate_policies),
        [RatePolicyId::parse(POLICY).unwrap()]
    );
}

#[tokio::test]
async fn the_command_carries_the_caller_the_values_and_fresh_identifiers() {
    let (app, commands, _queries, asked) = app(Answers::default());

    answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(commands.dispatched(), ["CreateRatePolicyCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].values.name, "per-subject");
    assert_eq!(sent[0].values.key_kind, RateKeyKind::SubjectRoute);
    assert_eq!(sent[0].values.limit, 100);
    assert_eq!(sent[0].values.period_ms, 60_000);
    assert_eq!(sent[0].values.burst, 20);
    assert_eq!(sent[0].values.fallback, RateFallback::Divided);
    assert_eq!(sent[0].idempotency, None);
    assert_ne!(
        sent[0].change_id.as_uuid(),
        sent[0].rate_policy_id.as_uuid()
    );
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
async fn a_creation_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());
    let mut anonymous = post(&[], CREATE_BODY);
    anonymous
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, _headers, body) = answer(app, anonymous).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::key(
    r#"{"name":"a","key":"everyone","limit":1,"periodMs":1000,"burst":0,"fallback":"full"}"#,
    "key"
)]
#[case::fallback(
    r#"{"name":"a","key":"ip","limit":1,"periodMs":1000,"burst":0,"fallback":"never"}"#,
    "fallback"
)]
#[tokio::test]
async fn a_name_that_is_no_choice_is_a_422_problem_naming_it_and_dispatches_nothing(
    #[case] body: &str,
    #[case] property: &str,
) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, post(&[], body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(problem["violations"][0]["code"], json!("enum"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::missing_members(r#"{"name":"a"}"#)]
#[case::unknown_member(
    r#"{"name":"a","key":"ip","limit":1,"periodMs":1000,"burst":0,"fallback":"full","x":1}"#
)]
#[case::not_json("name=a")]
#[tokio::test]
async fn a_malformed_body_is_a_client_error_and_dispatches_nothing(#[case] body: &str) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, post(&[], body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_duplicate_name_is_the_409_problem() {
    let answers = Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["status"], json!(409));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn values_that_the_command_refuses_are_a_422_problem_with_their_violations() {
    let answers = Answers {
        command: Err(|| {
            IamError::Invalid(vec![Violation {
                property_path: "periodMs".to_owned(),
                message: "This value must be a whole number of seconds.".to_owned(),
                code: "range".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("periodMs"));
}

#[tokio::test]
async fn a_new_idempotency_key_travels_with_the_command_and_a_replay_dispatches_nothing() {
    let (first, _commands, queries, asked) = app(Answers::default());
    let key = [("Idempotency-Key", "create-policy")];

    let (status, _headers, _body) = answer(first, post(&key, CREATE_BODY)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetRatePolicyQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays[0].request.key.as_str(), "create-policy");
    assert_eq!(
        recorded(&asked.commands)[0].idempotency,
        Some(replays[0].request.clone())
    );

    let replayed = Answers {
        replay: Ok(Some(receipt(Some(7)))),
        ..Answers::default()
    };
    let (second, commands, queries, _asked) = app(replayed);
    let (status, headers, body) = answer(second, post(&key, CREATE_BODY)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, policy_json(1));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetRatePolicyQuery"]
    );
}

#[tokio::test]
async fn a_key_reused_for_another_request_is_a_422_problem() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) =
        answer(app, post(&[("Idempotency-Key", "k")], CREATE_BODY)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_policy_is_read_with_its_etag() {
    let answers = Answers {
        rate_policy: Ok(Some(rate_policy(3))),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, headers, body) = answer(app, get(&item(POLICY))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"3\"".to_owned()));
    assert_eq!(body, policy_json(3));
}

#[tokio::test]
async fn an_unknown_policy_is_404_and_an_id_that_is_no_uuid_is_422() {
    let missing = Answers {
        rate_policy: Ok(None),
        ..Answers::default()
    };
    let (app_missing, _c, _q, _a) = app(missing);
    let (app_invalid, commands, queries, _a) = app(Answers::default());

    let (status, _headers, _body) = answer(app_missing, get(&item(POLICY))).await;
    let (invalid, _headers, problem) = answer(app_invalid, get(&item("nope"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(invalid, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_update_names_the_version_and_the_members_and_answers_with_the_new_state() {
    let answers = Answers {
        receipt: receipt_at(2, Some(6)),
        rate_policy: Ok(Some(rate_policy(2))),
        ..Answers::default()
    };
    let (app, commands, _queries, asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        request(
            Method::PATCH,
            &item(POLICY),
            &[("If-Match", "\"1\"")],
            Some(r#"{"limit":200,"key":"ip"}"#),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("6".to_owned()));
    assert_eq!(body, policy_json(2));
    assert_eq!(commands.dispatched(), ["UpdateRatePolicyCommand"]);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].patch.limit, Some(200));
    assert_eq!(sent[0].patch.key_kind, Some(RateKeyKind::Ip));
    assert_eq!(sent[0].patch.name, None);
}

#[rstest]
#[case::without_if_match(&[], StatusCode::PRECONDITION_REQUIRED)]
#[case::malformed_if_match(&[("If-Match", "1")], StatusCode::PRECONDITION_FAILED)]
#[tokio::test]
async fn an_update_without_a_matching_version_is_refused_before_dispatch(
    #[case] headers: &[(&str, &str)],
    #[case] expected: StatusCode,
) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(
        app,
        request(Method::PATCH, &item(POLICY), headers, Some("{}")),
    )
    .await;

    assert_eq!(status, expected);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_stale_version_is_the_412_problem() {
    let answers = Answers {
        update: Err(|| IamError::PreconditionFailed),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(
        app,
        request(
            Method::PATCH,
            &item(POLICY),
            &[("If-Match", "\"1\"")],
            Some("{}"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn a_deletion_answers_with_the_policy_and_its_final_version() {
    let answers = Answers {
        receipt: receipt_at(2, Some(8)),
        ..Answers::default()
    };
    let (app, commands, queries, asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        request(
            Method::DELETE,
            &item(POLICY),
            &[("If-Match", "\"1\"")],
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("8".to_owned()));
    assert_eq!(body, json!({ "id": POLICY, "version": 2 }));
    assert_eq!(commands.dispatched(), ["DeleteRatePolicyCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    assert_eq!(recorded(&asked.deletions)[0].expected.value(), 1);
}

#[tokio::test]
async fn a_policy_that_a_route_references_is_the_409_problem() {
    let answers = Answers {
        delete: Err(|| IamError::ReferencedByRoute),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(
        app,
        request(
            Method::DELETE,
            &item(POLICY),
            &[("If-Match", "\"1\"")],
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["type"], json!("/problems/referenced-by-route"));
}

#[tokio::test]
async fn the_list_reads_a_page_with_the_default_size_and_names_its_cursor() {
    let answers = Answers {
        page: Ok(RatePolicyPage {
            rate_policies: vec![rate_policy(1)],
            next_after: Some(RatePolicyId::parse(POLICY).unwrap()),
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);

    let (status, _headers, body) = answer(app, get("/rate-policies")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "items": [policy_json(1)], "nextCursor": POLICY })
    );
    let sent = recorded(&asked.lists);
    assert_eq!(sent[0].limit, 30);
    assert_eq!(sent[0].after, None);
}

#[rstest]
#[case::zero("/rate-policies?limit=0", "limit")]
#[case::too_large("/rate-policies?limit=101", "limit")]
#[case::bad_cursor("/rate-policies?after=nope", "after")]
#[tokio::test]
async fn invalid_list_parameters_are_a_422_problem_naming_them(
    #[case] uri: &str,
    #[case] property: &str,
) {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replayed_update_answers_with_the_stored_state_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(6)))),
        rate_policy: Ok(Some(rate_policy(2))),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        request(
            Method::PATCH,
            &item(POLICY),
            &[("If-Match", "\"1\""), ("Idempotency-Key", "update-policy")],
            Some(r#"{"limit":200}"#),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "iam-policy-version"), Some("6".to_owned()));
    assert_eq!(body, policy_json(2));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetRatePolicyQuery"]
    );
}

#[tokio::test]
async fn a_replayed_deletion_answers_with_the_stored_receipt_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(8)))),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        request(
            Method::DELETE,
            &item(POLICY),
            &[("If-Match", "\"1\""), ("Idempotency-Key", "delete-policy")],
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "iam-policy-version"), Some("8".to_owned()));
    assert_eq!(body, json!({ "id": POLICY, "version": 2 }));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["GetIdempotentReplayQuery"]);
}

#[tokio::test]
async fn a_failing_read_is_the_500_problem() {
    let answers = Answers {
        rate_policy: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    };
    let (read_app, _commands, _queries, _asked) = app(answers);
    let failing_list = Answers {
        page: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    };
    let (list_app, _commands, _queries, _asked) = app(failing_list);

    let (read, _headers, _problem) = answer(read_app, get(&item(POLICY))).await;
    let (list, _headers, _problem) = answer(list_app, get("/rate-policies")).await;

    assert_eq!(read, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(list, StatusCode::INTERNAL_SERVER_ERROR);
}
