use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{ActorRef, RoleId, RoleKind};
use rstest::rstest;
use serde_json::{Value, json};
use shared_domain::Uuid;
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::command::update_role::DescriptionUpdate;
use crate::error::IamError;
use crate::fixtures::{
    Answers, Asked, ROLE, USER, principal, receipt, receipt_at, recorded, role, scenario,
};
use crate::http::{IamState, router};
use crate::query::list_roles::{ListRolesQuery, RolePage};

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
    request(Method::POST, "/roles", headers, Some(body))
}

fn get(uri: &str) -> Request<Body> {
    request(Method::GET, uri, &[], None)
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

fn role_json(version: i64) -> Value {
    json!({
        "id": ROLE,
        "name": "Billing",
        "description": "Invoices",
        "kind": "custom",
        "grantCount": 0,
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:01:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_role_is_201_with_its_location_etag_and_data() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, headers, body) = answer(
        app,
        post(&[], r#"{"name":"Billing","description":"Invoices"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/roles/{ROLE}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), None);
    assert_eq!(body, role_json(1));
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery", "GetRoleQuery"]);
    assert_eq!(recorded(&asked.roles), [RoleId::parse(ROLE).unwrap()]);
}

#[tokio::test]
async fn the_command_carries_the_caller_the_fields_and_fresh_identifiers() {
    let (app, commands, _queries, asked) = app(Answers::default());

    answer(
        app,
        post(&[], r#"{"name":"Billing","description":"Invoices"}"#),
    )
    .await;

    assert_eq!(commands.dispatched(), ["CreateRoleCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].name, "Billing");
    assert_eq!(sent[0].description.as_deref(), Some("Invoices"));
    assert_eq!(sent[0].idempotency, None);
    assert_ne!(sent[0].change_id.as_uuid(), sent[0].role_id.as_uuid());
}

#[tokio::test]
async fn a_policy_version_of_the_receipt_is_a_response_header() {
    let answers = Answers {
        receipt: receipt(Some(5)),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, headers, _body) = answer(app, post(&[], r#"{"name":"Billing"}"#)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header(&headers, "iam-policy-version"), Some("5".to_owned()));
}

#[tokio::test]
async fn a_creation_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, anonymous(post(&[], r#"{"name":"Billing"}"#))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::empty_name(r#"{"name":""}"#, "name")]
#[case::long_name(&format!(r#"{{"name":"{}"}}"#, "n".repeat(101)), "name")]
#[case::long_description(&format!(r#"{{"name":"a","description":"{}"}}"#, "d".repeat(1001)), "description")]
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
#[case::missing_name("{}")]
#[case::unknown_member(r#"{"name":"a","kind":"system"}"#)]
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

    let (status, _headers, problem) = answer(app, post(&[], r#"{"name":"Billing"}"#)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["status"], json!(409));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_name_that_the_domain_refuses_is_a_422_problem_with_its_violations() {
    let answers = Answers {
        command: Err(|| IamError::from(vec![iam_domain::InvalidRole::NameControlCharacter])),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], r#"{"name":"a"}"#)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["code"], json!("control_character"));
}

#[tokio::test]
async fn a_new_idempotency_key_creates_the_role_and_travels_with_the_command() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, _headers, _body) = answer(
        app,
        post(
            &[("Idempotency-Key", "create-billing")],
            r#"{"name":"Billing"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetRoleQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays.len(), 1);
    assert_eq!(replays[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(replays[0].request.key.as_str(), "create-billing");
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].idempotency, Some(replays[0].request.clone()));
}

#[tokio::test]
async fn the_same_key_with_another_body_has_another_digest() {
    let (first, _c1, _q1, asked_first) = app(Answers::default());
    let (second, _c2, _q2, asked_second) = app(Answers::default());
    let key = [("Idempotency-Key", "create-billing")];

    answer(first, post(&key, r#"{"name":"Billing"}"#)).await;
    answer(second, post(&key, r#"{"name":"Support"}"#)).await;

    let digests: Vec<_> = [asked_first, asked_second]
        .iter()
        .map(|asked| recorded(&asked.replays)[0].request.request_digest)
        .collect();
    assert_ne!(digests[0], digests[1]);
}

#[tokio::test]
async fn a_replayed_creation_returns_the_original_result_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt(Some(7)))),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        post(
            &[("Idempotency-Key", "create-billing")],
            r#"{"name":"Billing"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/roles/{ROLE}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, role_json(1));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetRoleQuery"]
    );
}

#[tokio::test]
async fn a_key_reused_for_another_request_is_a_422_problem_and_dispatches_nothing() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(
        app,
        post(
            &[("Idempotency-Key", "create-billing")],
            r#"{"name":"Billing"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["detail"],
        json!("The idempotency key was already used for a different request.")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_invalid_idempotency_key_is_a_422_problem_naming_the_key() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(
        app,
        post(&[("Idempotency-Key", "not valid")], r#"{"name":"Billing"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["violations"][0]["propertyPath"],
        json!("idempotencyKey")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_created_role_that_cannot_be_read_back_is_a_404_problem() {
    let answers = Answers {
        role: Ok(None),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, post(&[], r#"{"name":"Billing"}"#)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_receipt_that_names_no_role_is_an_internal_problem() {
    let wrong = iam_domain::ChangeReceipt::new(
        receipt(None).change_id(),
        receipt(None).actor().clone(),
        iam_domain::AuditTarget::new("role", "not-a-uuid").unwrap(),
        iam_domain::EntityVersion::INITIAL,
        None,
    );
    let answers = Answers {
        receipt: wrong,
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, post(&[], r#"{"name":"Billing"}"#)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_failing_command_bus_is_an_internal_problem() {
    let answers = Answers {
        command: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], r#"{"name":"Billing"}"#)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!problem.to_string().contains("disk on fire"));
}

#[tokio::test]
async fn a_stored_role_is_read_with_its_etag() {
    let answers = Answers {
        role: Ok(Some(role(3))),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);

    let (status, headers, body) = answer(app, get(&format!("/roles/{ROLE}"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"3\"".to_owned()));
    assert_eq!(body, role_json(3));
    assert_eq!(recorded(&asked.roles), [RoleId::parse(ROLE).unwrap()]);
}

#[tokio::test]
async fn an_unknown_role_is_the_404_problem() {
    let answers = Answers {
        role: Ok(None),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, get(&format!("/roles/{ROLE}"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["status"], json!(404));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_naming_the_id() {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, get("/roles/not-a-uuid")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[rstest]
#[case::item(format!("/roles/{ROLE}"))]
#[case::collection("/roles".to_owned())]
#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem(#[case] uri: String) {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, anonymous(get(&uri))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_role_read_is_an_internal_problem() {
    let answers = Answers {
        role: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, get(&format!("/roles/{ROLE}"))).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn the_list_without_parameters_asks_for_the_first_page_of_thirty() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, get("/roles")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "items": [] }));
    assert_eq!(
        recorded(&asked.lists),
        [ListRolesQuery {
            limit: 30,
            after: None,
            name_prefix: None,
            kind: None,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_its_parameters_and_answers_the_page_with_its_cursor() {
    let answers = Answers {
        page: Ok(RolePage {
            roles: vec![role(2)],
            next_after: Some(RoleId::parse(ROLE).unwrap()),
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);
    let uri = format!("/roles?limit=1&after={ROLE}&namePrefix=bill&kind=system");

    let (status, _headers, body) = answer(app, get(&uri)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "items": [role_json(2)], "nextCursor": ROLE }));
    assert_eq!(
        recorded(&asked.lists),
        [ListRolesQuery {
            limit: 1,
            after: Some(RoleId::parse(ROLE).unwrap()),
            name_prefix: Some("bill".to_owned()),
            kind: Some(RoleKind::System),
        }]
    );
}

#[rstest]
#[case::zero("/roles?limit=0", "limit")]
#[case::above("/roles?limit=101", "limit")]
#[case::negative("/roles?limit=-1", "limit")]
#[case::kind("/roles?kind=owner", "kind")]
#[case::cursor("/roles?after=x", "after")]
#[tokio::test]
async fn an_invalid_list_parameter_is_a_422_problem_naming_it(
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
async fn an_unknown_list_parameter_is_a_client_error() {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, get("/roles?sort=name")).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_list_is_an_internal_problem() {
    let answers = Answers {
        page: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, get("/roles")).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

fn patch(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(
        Method::PATCH,
        &format!("/roles/{ROLE}"),
        headers,
        Some(body),
    )
}

fn updated(version: i64) -> Answers {
    Answers {
        receipt: receipt_at(version, None),
        role: Ok(Some(role(version))),
        ..Answers::default()
    }
}

#[tokio::test]
async fn an_updated_role_is_200_with_its_new_etag_and_data() {
    let (app, commands, queries, asked) = app(updated(2));

    let (status, headers, body) = answer(
        app,
        patch(&[("If-Match", "\"1\"")], r#"{"name":"Accounting"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, LOCATION.as_str()), None);
    assert_eq!(header(&headers, "iam-policy-version"), None);
    assert_eq!(body, role_json(2));
    assert_eq!(commands.dispatched(), ["UpdateRoleCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery", "GetRoleQuery"]);
    let sent = recorded(&asked.updates);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].name.as_deref(), Some("Accounting"));
    assert_eq!(sent[0].description, DescriptionUpdate::Keep);
    assert_eq!(sent[0].idempotency, None);
}

#[rstest]
#[case::absent(r#"{"name":"a"}"#, DescriptionUpdate::Keep)]
#[case::null(r#"{"description":null}"#, DescriptionUpdate::Remove)]
#[case::text(r#"{"description":"Refunds"}"#, DescriptionUpdate::Set("Refunds".to_owned()))]
#[tokio::test]
async fn the_description_member_keeps_removes_or_replaces_the_description(
    #[case] body: &str,
    #[case] expected: DescriptionUpdate,
) {
    let (app, _commands, _queries, asked) = app(updated(2));

    let (status, _headers, _body) = answer(app, patch(&[("If-Match", "\"1\"")], body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(recorded(&asked.updates)[0].description, expected);
}

#[tokio::test]
async fn the_policy_version_of_the_receipt_is_a_response_header_of_an_update() {
    let answers = Answers {
        receipt: receipt_at(2, Some(9)),
        ..updated(2)
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (_status, headers, _body) =
        answer(app, patch(&[("If-Match", "\"1\"")], r#"{"name":"a"}"#)).await;

    assert_eq!(header(&headers, "iam-policy-version"), Some("9".to_owned()));
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, patch(&[], r#"{"name":"a"}"#)).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(problem["status"], json!(428));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::weak("W/\"1\"")]
#[case::unquoted("1")]
#[case::zero("\"0\"")]
#[tokio::test]
async fn an_if_match_that_is_no_etag_is_the_412_problem_and_dispatches_nothing(
    #[case] value: &str,
) {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) =
        answer(app, patch(&[("If-Match", value)], r#"{"name":"a"}"#)).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["status"], json!(412));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::system_role(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[case::duplicate_name(|| IamError::Conflict, StatusCode::CONFLICT)]
#[tokio::test]
async fn a_refused_update_is_its_problem_and_reads_nothing_back(
    #[case] refusal: crate::fixtures::Refusal,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        update: Err(refusal),
        ..updated(2)
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) =
        answer(app, patch(&[("If-Match", "\"1\"")], r#"{"name":"a"}"#)).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[rstest]
#[case::empty_name(r#"{"name":""}"#, "name")]
#[case::long_name(&format!(r#"{{"name":"{}"}}"#, "n".repeat(101)), "name")]
#[case::long_description(&format!(r#"{{"description":"{}"}}"#, "d".repeat(1001)), "description")]
#[tokio::test]
async fn an_invalid_field_of_an_update_is_a_422_problem_naming_it(
    #[case] body: &str,
    #[case] property: &str,
) {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, patch(&[("If-Match", "\"1\"")], body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(problem["violations"][0]["code"], json!("length"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::unknown_member(r#"{"kind":"system"}"#)]
#[case::not_json("name=a")]
#[tokio::test]
async fn a_malformed_update_body_is_a_client_error_and_dispatches_nothing(#[case] body: &str) {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, _problem) = answer(app, patch(&[("If-Match", "\"1\"")], body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_update_with_an_id_that_is_no_uuid_is_a_422_problem() {
    let (app, commands, _queries, _asked) = app(updated(2));
    let request = request(
        Method::PATCH,
        "/roles/nope",
        &[("If-Match", "\"1\"")],
        Some(r#"{"name":"a"}"#),
    );

    let (status, _headers, problem) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_update_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, _body) = answer(
        app,
        anonymous(patch(&[("If-Match", "\"1\"")], r#"{"name":"a"}"#)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_updated_role_that_is_gone_when_read_back_is_the_404_problem() {
    let answers = Answers {
        role: Ok(None),
        ..updated(2)
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) =
        answer(app, patch(&[("If-Match", "\"1\"")], r#"{"name":"a"}"#)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_new_idempotency_key_updates_the_role_and_travels_with_the_command() {
    let (app, _commands, queries, asked) = app(updated(2));

    let (status, _headers, _body) = answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "rename-billing")],
            r#"{"name":"Accounting"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetRoleQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays[0].request.key.as_str(), "rename-billing");
    assert_eq!(
        recorded(&asked.updates)[0].idempotency,
        Some(replays[0].request.clone())
    );
}

#[tokio::test]
async fn the_same_key_for_another_version_or_body_has_another_digest() {
    let key = ("Idempotency-Key", "rename-billing");
    let requests = [
        patch(&[("If-Match", "\"1\""), key], r#"{"name":"a"}"#),
        patch(&[("If-Match", "\"2\""), key], r#"{"name":"a"}"#),
        patch(&[("If-Match", "\"1\""), key], r#"{"name":"b"}"#),
    ];
    let mut digests = Vec::new();
    for request in requests {
        let (app, _commands, _queries, asked) = app(updated(2));
        answer(app, request).await;
        digests.push(recorded(&asked.replays)[0].request.request_digest);
    }

    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[0], digests[2]);
    assert_ne!(digests[1], digests[2]);
}

#[tokio::test]
async fn a_replayed_update_returns_the_original_receipt_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(7)))),
        ..updated(2)
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "rename-billing")],
            r#"{"name":"Accounting"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, role_json(2));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetRoleQuery"]
    );
}

#[tokio::test]
async fn a_key_reused_for_another_update_is_a_422_problem_and_dispatches_nothing() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..updated(2)
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(
        app,
        patch(
            &[("If-Match", "\"1\""), ("Idempotency-Key", "rename-billing")],
            r#"{"name":"a"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

fn delete(headers: &[(&str, &str)]) -> Request<Body> {
    request(Method::DELETE, &format!("/roles/{ROLE}"), headers, None)
}

/// The answers of a deletion that revoked `revoked` assignments and took policy version 5.
fn deleted(revoked: u32) -> Answers {
    Answers {
        receipt: receipt_at(2, Some(5)).with_revoked_assignments(revoked),
        ..Answers::default()
    }
}

#[tokio::test]
async fn a_deleted_role_is_200_with_the_revoked_assignments_the_final_etag_and_the_policy_version()
{
    let (app, commands, queries, asked) = app(deleted(3));

    let (status, headers, body) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("5".to_owned()));
    assert_eq!(body, json!({ "id": ROLE, "revokedAssignments": 3 }));
    assert_eq!(commands.dispatched(), ["DeleteRoleCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_deletion_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(deleted(0));

    let (status, _headers, problem) =
        answer(app, anonymous(delete(&[("If-Match", "\"1\"")]))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_deletion_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(deleted(0));

    let (status, _headers, problem) = answer(app, delete(&[])).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(problem["status"], json!(428));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_deletion_with_an_if_match_that_is_no_etag_is_the_412_problem() {
    let (app, commands, _queries, _asked) = app(deleted(0));

    let (status, _headers, problem) = answer(app, delete(&[("If-Match", "W/\"1\"")])).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["status"], json!(412));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::system_role(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[case::concurrent(|| IamError::Conflict, StatusCode::CONFLICT)]
#[case::storage(|| IamError::Storage("disk on fire".into()), StatusCode::INTERNAL_SERVER_ERROR)]
#[tokio::test]
async fn a_refused_deletion_is_its_problem_and_reads_nothing_back(
    #[case] refusal: crate::fixtures::Refusal,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        delete: Err(refusal),
        ..deleted(0)
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_deletion_with_an_id_that_is_no_uuid_is_a_422_problem() {
    let (app, commands, _queries, _asked) = app(deleted(0));
    let request = request(
        Method::DELETE,
        "/roles/nope",
        &[("If-Match", "\"1\"")],
        None,
    );

    let (status, _headers, problem) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_deletion_key_travels_with_the_command_and_a_replay_returns_the_original_count() {
    let (app_new, _commands, _queries, asked) = app(deleted(3));
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(7)).with_revoked_assignments(3))),
        ..deleted(0)
    };
    let (app_replay, commands, queries, _replayed) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "delete-billing")];

    let (status, _headers, _body) = answer(app_new, delete(&headers)).await;
    let (replay_status, replay_headers, replay_body) = answer(app_replay, delete(&headers)).await;

    assert_eq!(status, StatusCode::OK);
    let key = recorded(&asked.deletions)[0].idempotency.clone().unwrap();
    assert_eq!(key.key.as_str(), "delete-billing");
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(
        header(&replay_headers, "iam-policy-version"),
        Some("7".to_owned())
    );
    assert_eq!(replay_body, json!({ "id": ROLE, "revokedAssignments": 3 }));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["GetIdempotentReplayQuery"]);
}

#[tokio::test]
async fn a_deletion_key_reused_for_another_request_is_a_422_problem() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..deleted(0)
    };
    let (app, commands, _queries, _asked) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "delete-billing")];

    let (status, _headers, _problem) = answer(app, delete(&headers)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}
