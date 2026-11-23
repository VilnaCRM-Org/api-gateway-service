use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{
    ActorRef, AssignmentScope, ChangeReceipt, ProjectId, RoleId, SubjectKind, SubjectRef,
    UserRoleId,
};
use rstest::rstest;
use serde_json::{Value, json};
use shared_domain::Uuid;
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{ROLE, USER, principal, recorded};
use crate::http::{IamState, router};
use crate::query::list_user_roles::{ListUserRolesQuery, UserRolePage};
use crate::user_role_fixtures::{
    Answers, Asked, PROJECT, SUBJECT, USER_ROLE, receipt, receipt_at, scenario, user_role,
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
    request(Method::POST, "/user-roles", headers, Some(body))
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

fn body() -> String {
    json!({
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
    })
    .to_string()
}

fn user_role_json(version: i64) -> Value {
    json!({
        "id": USER_ROLE,
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "roleName": "Billing",
        "scope": { "kind": "global" },
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:01:00.000000Z",
    })
}

#[tokio::test]
async fn an_assignment_is_201_with_its_location_etag_policy_version_and_data() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, headers, response) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/user-roles/{USER_ROLE}"))
    );
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"1\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("1".to_owned()));
    assert_eq!(response, user_role_json(1));
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetUserRoleQuery"]
    );
    assert_eq!(
        recorded(&asked.user_roles),
        [UserRoleId::parse(USER_ROLE).unwrap()]
    );
}

#[tokio::test]
async fn the_command_carries_the_caller_the_values_and_fresh_identifiers() {
    let (app, commands, _queries, asked) = app(Answers::default());
    let project = json!({
        "subject": { "kind": "service", "id": "billing-worker" },
        "roleId": ROLE,
        "scope": { "kind": "project", "projectId": PROJECT },
        "expiresAt": "2027-01-15T08:00:00Z",
    })
    .to_string();

    answer(app, post(&[], &project)).await;

    assert_eq!(commands.dispatched(), ["AssignUserRoleCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].subject.to_string(), "service:billing-worker");
    assert_eq!(sent[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(
        sent[0].scope,
        AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
    );
    assert!(sent[0].expires_at.is_some());
    assert_eq!(sent[0].idempotency, None);
    assert_ne!(sent[0].change_id.as_uuid(), sent[0].user_role_id.as_uuid());
}

#[tokio::test]
async fn a_user_subject_reaches_the_command_as_a_user() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    answer(app, post(&[], &body())).await;

    let sent = recorded(&asked.commands);
    assert_eq!(
        sent[0].subject,
        SubjectRef::user(Uuid::parse(SUBJECT).unwrap())
    );
    assert_eq!(sent[0].scope, AssignmentScope::Global);
    assert_eq!(sent[0].expires_at, None);
}

#[tokio::test]
async fn an_assignment_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, anonymous(post(&[], &body()))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::kind(json!({"subject": {"kind": "robot", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.kind", "choice")]
#[case::user_id(json!({"subject": {"kind": "user", "id": "x"}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.id", "uuid")]
#[case::role_id(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": "x", "scope": {"kind": "global"}}), "roleId", "uuid")]
#[case::scope(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "project"}}), "scope.projectId", "required")]
#[case::expiry(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}, "expiresAt": "soon"}), "expiresAt", "format")]
#[case::empty_kind(json!({"subject": {"kind": "", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.kind", "length")]
#[tokio::test]
async fn an_invalid_value_is_a_422_problem_naming_it_and_dispatches_nothing(
    #[case] request_body: Value,
    #[case] property: &str,
    #[case] code: &str,
) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, post(&[], &request_body.to_string())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(problem["violations"][0]["code"], json!(code));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::missing_subject(r#"{"roleId":"x","scope":{"kind":"global"}}"#)]
#[case::unknown_member(
    r#"{"subject":{"kind":"user","id":"x"},"roleId":"x","scope":{"kind":"global"},"extra":1}"#
)]
#[case::not_json("subject=a")]
#[tokio::test]
async fn a_malformed_body_is_a_client_error_and_dispatches_nothing(#[case] malformed: &str) {
    let (app, commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, post(&[], malformed)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_duplicate_assignment_is_the_409_problem() {
    let answers = Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["status"], json!(409));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_unknown_role_refused_by_the_command_is_a_422_problem_naming_the_role_id() {
    let answers = Answers {
        command: Err(|| {
            IamError::Invalid(vec![shared_application::http::Violation {
                property_path: "roleId".to_owned(),
                message: "This role does not exist.".to_owned(),
                code: "exists".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("roleId"));
    assert_eq!(problem["violations"][0]["code"], json!("exists"));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_past_expiry_refused_by_the_command_is_a_422_problem_naming_expires_at() {
    let answers = Answers {
        command: Err(|| {
            IamError::Invalid(vec![shared_application::http::Violation {
                property_path: "expiresAt".to_owned(),
                message: "This value must be a time in the future.".to_owned(),
                code: "future".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("expiresAt"));
    assert_eq!(problem["violations"][0]["code"], json!("future"));
}

#[tokio::test]
async fn a_new_idempotency_key_assigns_the_role_and_travels_with_the_command() {
    let (app, _commands, queries, asked) = app(Answers::default());

    let (status, _headers, _body) =
        answer(app, post(&[("Idempotency-Key", "assign-billing")], &body())).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetUserRoleQuery"
        ]
    );
    let replays = recorded(&asked.replays);
    assert_eq!(replays.len(), 1);
    assert_eq!(replays[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(replays[0].request.key.as_str(), "assign-billing");
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].idempotency, Some(replays[0].request.clone()));
}

#[tokio::test]
async fn the_same_key_with_another_body_has_another_digest() {
    let (first, _c1, _q1, asked_first) = app(Answers::default());
    let (second, _c2, _q2, asked_second) = app(Answers::default());
    let key = [("Idempotency-Key", "assign-billing")];
    let other = json!({
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "project", "projectId": PROJECT },
    })
    .to_string();

    answer(first, post(&key, &body())).await;
    answer(second, post(&key, &other)).await;

    let digests: Vec<_> = [asked_first, asked_second]
        .iter()
        .map(|asked| recorded(&asked.replays)[0].request.request_digest)
        .collect();
    assert_ne!(digests[0], digests[1]);
}

#[tokio::test]
async fn a_replayed_assignment_returns_the_original_result_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt(Some(7)))),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, response) =
        answer(app, post(&[("Idempotency-Key", "assign-billing")], &body())).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        header(&headers, LOCATION.as_str()),
        Some(format!("/api/user-roles/{USER_ROLE}"))
    );
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(response, user_role_json(1));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetUserRoleQuery"]
    );
}

#[tokio::test]
async fn a_key_reused_for_another_request_is_a_422_problem_and_dispatches_nothing() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) =
        answer(app, post(&[("Idempotency-Key", "assign-billing")], &body())).await;

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

    let (status, _headers, problem) =
        answer(app, post(&[("Idempotency-Key", "not valid")], &body())).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["violations"][0]["propertyPath"],
        json!("idempotencyKey")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_assignment_that_cannot_be_read_back_is_a_404_problem() {
    let answers = Answers {
        user_role: Ok(None),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_receipt_that_names_no_assignment_is_an_internal_problem() {
    let wrong = ChangeReceipt::new(
        receipt(None).change_id(),
        receipt(None).actor().clone(),
        iam_domain::AuditTarget::new("user_role", "not-a-uuid").unwrap(),
        iam_domain::EntityVersion::INITIAL,
        None,
    );
    let answers = Answers {
        receipt: wrong,
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_failing_command_bus_is_an_internal_problem() {
    let answers = Answers {
        command: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, post(&[], &body())).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!problem.to_string().contains("disk on fire"));
}

#[tokio::test]
async fn a_stored_assignment_is_read_with_its_etag() {
    let answers = Answers {
        user_role: Ok(Some(user_role(3))),
        ..Answers::default()
    };
    let (app, _commands, _queries, asked) = app(answers);

    let (status, headers, response) = answer(app, get(&format!("/user-roles/{USER_ROLE}"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"3\"".to_owned()));
    assert_eq!(response, user_role_json(3));
    assert_eq!(
        recorded(&asked.user_roles),
        [UserRoleId::parse(USER_ROLE).unwrap()]
    );
}

#[tokio::test]
async fn an_unknown_assignment_is_the_404_problem() {
    let answers = Answers {
        user_role: Ok(None),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, get(&format!("/user-roles/{USER_ROLE}"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["status"], json!(404));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_naming_the_id() {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, get("/user-roles/not-a-uuid")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[rstest]
#[case::item(format!("/user-roles/{USER_ROLE}"))]
#[case::collection("/user-roles".to_owned())]
#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem(#[case] uri: String) {
    let (app, _commands, queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, anonymous(get(&uri))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_assignment_read_is_an_internal_problem() {
    let answers = Answers {
        user_role: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, get(&format!("/user-roles/{USER_ROLE}"))).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn the_list_without_parameters_asks_for_the_first_page_of_thirty() {
    let (app, _commands, _queries, asked) = app(Answers::default());

    let (status, _headers, response) = answer(app, get("/user-roles")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, json!({ "items": [] }));
    assert_eq!(
        recorded(&asked.lists),
        [ListUserRolesQuery {
            limit: 30,
            after: None,
            subject_kind: None,
            subject_id: None,
            role_id: None,
            project_id: None,
            include_expired: false,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_every_filter_and_the_cursor_to_the_query() {
    let (app, _commands, _queries, asked) = app(Answers::default());
    let uri = format!(
        "/user-roles?limit=5&after={USER_ROLE}&subjectKind=service&subjectId=billing-worker&roleId={ROLE}&projectId={PROJECT}&includeExpired=true"
    );

    let (status, _headers, _response) = answer(app, get(&uri)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        recorded(&asked.lists),
        [ListUserRolesQuery {
            limit: 5,
            after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
            subject_kind: Some(SubjectKind::Service),
            subject_id: Some("billing-worker".to_owned()),
            role_id: Some(RoleId::parse(ROLE).unwrap()),
            project_id: Some(ProjectId::parse(PROJECT).unwrap()),
            include_expired: true,
        }]
    );
}

#[tokio::test]
async fn a_page_of_assignments_is_listed_with_its_cursor() {
    let answers = Answers {
        page: Ok(UserRolePage {
            user_roles: vec![user_role(2)],
            next_after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
        }),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, response) = answer(app, get("/user-roles")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response,
        json!({ "items": [user_role_json(2)], "nextCursor": USER_ROLE })
    );
}

#[rstest]
#[case::limit("/user-roles?limit=0", "limit")]
#[case::large_limit("/user-roles?limit=101", "limit")]
#[case::cursor("/user-roles?after=x", "after")]
#[case::kind("/user-roles?subjectKind=robot", "subjectKind")]
#[case::role("/user-roles?roleId=x", "roleId")]
#[case::project("/user-roles?projectId=x", "projectId")]
#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_naming_it(
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
async fn an_unknown_query_parameter_is_a_client_error() {
    let (app, _commands, _queries, _asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, get("/user-roles?colour=red")).await;

    assert!(status.is_client_error(), "{status}");
}

#[tokio::test]
async fn a_failing_assignment_list_is_an_internal_problem() {
    let answers = Answers {
        page: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) = answer(app, get("/user-roles")).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

fn patch(headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(
        Method::PATCH,
        &format!("/user-roles/{USER_ROLE}"),
        headers,
        Some(body),
    )
}

fn delete(headers: &[(&str, &str)]) -> Request<Body> {
    request(
        Method::DELETE,
        &format!("/user-roles/{USER_ROLE}"),
        headers,
        None,
    )
}

fn updated(version: i64) -> Answers {
    Answers {
        receipt: receipt_at(version, Some(5)),
        user_role: Ok(Some(user_role(version))),
        ..Answers::default()
    }
}

const NEW_EXPIRY: &str = r#"{"expiresAt":"2027-01-15T08:00:00Z"}"#;

#[tokio::test]
async fn an_updated_assignment_is_200_with_its_new_etag_policy_version_and_data() {
    let (app, commands, queries, asked) = app(updated(2));

    let (status, headers, body) = answer(app, patch(&[("If-Match", "\"1\"")], NEW_EXPIRY)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, LOCATION.as_str()), None);
    assert_eq!(header(&headers, "iam-policy-version"), Some("5".to_owned()));
    assert_eq!(body, user_role_json(2));
    assert_eq!(commands.dispatched(), ["UpdateUserRoleCommand"]);
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetUserRoleQuery"]
    );
    let sent = recorded(&asked.updates);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].user_role_id, UserRoleId::parse(USER_ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert!(sent[0].expires_at.is_some());
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_null_expiry_clears_the_expiry() {
    let (app, _commands, _queries, asked) = app(updated(2));

    let (status, _headers, _body) = answer(
        app,
        patch(&[("If-Match", "\"1\"")], r#"{"expiresAt":null}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(recorded(&asked.updates)[0].expires_at, None);
}

#[tokio::test]
async fn an_update_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, headers, problem) =
        answer(app, anonymous(patch(&[("If-Match", "\"1\"")], NEW_EXPIRY))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(header(&headers, "www-authenticate").is_some());
    assert_eq!(problem["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, patch(&[], NEW_EXPIRY)).await;

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

    let (status, _headers, problem) = answer(app, patch(&[("If-Match", value)], NEW_EXPIRY)).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["status"], json!(412));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[case::concurrent(|| IamError::Conflict, StatusCode::CONFLICT)]
#[case::past_expiry(
    || IamError::invalid_property("expiresAt", "This value must be in the future.", "future"),
    StatusCode::UNPROCESSABLE_ENTITY
)]
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
        answer(app, patch(&[("If-Match", "\"1\"")], NEW_EXPIRY)).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[rstest]
#[case::format(r#"{"expiresAt":"soon"}"#, "expiresAt", "format")]
#[case::long(&format!(r#"{{"expiresAt":"{}"}}"#, "2".repeat(41)), "expiresAt", "length")]
#[tokio::test]
async fn an_invalid_expiry_is_a_422_problem_naming_it_and_dispatches_nothing(
    #[case] body: &str,
    #[case] property: &str,
    #[case] code: &str,
) {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, patch(&[("If-Match", "\"1\"")], body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert_eq!(problem["violations"][0]["code"], json!(code));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::empty("{}")]
#[case::unknown_member(r#"{"expiresAt":null,"version":3}"#)]
#[case::not_text(r#"{"expiresAt":3}"#)]
#[case::not_json("expiresAt=soon")]
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
        "/user-roles/nope",
        &[("If-Match", "\"1\"")],
        Some(NEW_EXPIRY),
    );

    let (status, _headers, problem) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_new_update_key_travels_with_the_command_and_the_same_key_with_another_body_digests_differently()
 {
    let (app_one, _commands, _queries, one) = app(updated(2));
    let (app_two, _commands, _queries, two) = app(updated(2));
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "extend-billing")];

    let _first = answer(app_one, patch(&headers, NEW_EXPIRY)).await;
    let _second = answer(app_two, patch(&headers, r#"{"expiresAt":null}"#)).await;

    let first = recorded(&one.updates)[0].idempotency.clone().unwrap();
    let second = recorded(&two.updates)[0].idempotency.clone().unwrap();
    assert_eq!(first.key.as_str(), "extend-billing");
    assert_eq!(second.key, first.key);
    assert_ne!(second.request_digest, first.request_digest);
}

#[tokio::test]
async fn a_replayed_update_returns_the_original_result_and_dispatches_nothing() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(7)))),
        ..updated(2)
    };
    let (app, commands, queries, _asked) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "extend-billing")];

    let (status, headers, body) = answer(app, patch(&headers, NEW_EXPIRY)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "iam-policy-version"), Some("7".to_owned()));
    assert_eq!(body, user_role_json(2));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(
        queries.asked(),
        ["GetIdempotentReplayQuery", "GetUserRoleQuery"]
    );
}

#[tokio::test]
async fn an_update_key_reused_for_another_request_is_a_422_problem_and_dispatches_nothing() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..updated(2)
    };
    let (app, commands, _queries, _asked) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "extend-billing")];

    let (status, _headers, problem) = answer(app, patch(&headers, NEW_EXPIRY)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["detail"],
        json!("The idempotency key was already used for a different request.")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_updated_assignment_that_cannot_be_read_back_is_a_404_problem() {
    let answers = Answers {
        user_role: Ok(None),
        ..updated(2)
    };
    let (app, _commands, _queries, _asked) = app(answers);

    let (status, _headers, _problem) =
        answer(app, patch(&[("If-Match", "\"1\"")], NEW_EXPIRY)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_revoked_assignment_is_204_with_the_final_etag_and_the_policy_version() {
    let (app, commands, queries, asked) = app(updated(2));

    let (status, headers, body) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"2\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("5".to_owned()));
    assert_eq!(body, Value::Null);
    assert_eq!(commands.dispatched(), ["RevokeUserRoleCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.revocations);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].user_role_id, UserRoleId::parse(USER_ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_revocation_without_a_token_is_the_401_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) =
        answer(app, anonymous(delete(&[("If-Match", "\"1\"")]))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem["status"], json!(401));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_revocation_without_if_match_is_the_428_problem_and_dispatches_nothing() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, delete(&[])).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(problem["status"], json!(428));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_revocation_with_an_if_match_that_is_no_etag_is_the_412_problem() {
    let (app, commands, _queries, _asked) = app(updated(2));

    let (status, _headers, problem) = answer(app, delete(&[("If-Match", "W/\"1\"")])).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["status"], json!(412));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::unknown(|| IamError::NotFound, StatusCode::NOT_FOUND)]
#[case::concurrent(|| IamError::Conflict, StatusCode::CONFLICT)]
#[case::storage(|| IamError::Storage("disk on fire".into()), StatusCode::INTERNAL_SERVER_ERROR)]
#[tokio::test]
async fn a_refused_revocation_is_its_problem_and_reads_nothing_back(
    #[case] refusal: crate::fixtures::Refusal,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        revoke: Err(refusal),
        ..updated(2)
    };
    let (app, _commands, queries, _asked) = app(answers);

    let (status, _headers, problem) = answer(app, delete(&[("If-Match", "\"1\"")])).await;

    assert_eq!(status, expected);
    assert_eq!(problem["status"], json!(expected.as_u16()));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_revocation_with_an_id_that_is_no_uuid_is_a_422_problem() {
    let (app, commands, _queries, _asked) = app(updated(2));
    let request = request(
        Method::DELETE,
        "/user-roles/nope",
        &[("If-Match", "\"1\"")],
        None,
    );

    let (status, _headers, problem) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_revocation_key_travels_with_the_command_and_a_replay_dispatches_nothing() {
    let (app_new, _commands, _queries, asked) = app(updated(2));
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(7)))),
        ..updated(2)
    };
    let (app_replay, commands, queries, _replayed) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "revoke-billing")];

    let (status, _headers, _body) = answer(app_new, delete(&headers)).await;
    let (replay_status, replay_headers, _body) = answer(app_replay, delete(&headers)).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let key = recorded(&asked.revocations)[0].idempotency.clone().unwrap();
    assert_eq!(key.key.as_str(), "revoke-billing");
    assert_eq!(replay_status, StatusCode::NO_CONTENT);
    assert_eq!(
        header(&replay_headers, "iam-policy-version"),
        Some("7".to_owned())
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["GetIdempotentReplayQuery"]);
}

#[tokio::test]
async fn a_revocation_key_reused_for_another_request_is_a_422_problem() {
    let answers = Answers {
        replay: Err(|| IamError::IdempotencyMismatch),
        ..updated(2)
    };
    let (app, commands, _queries, _asked) = app(answers);
    let headers = [("If-Match", "\"1\""), ("Idempotency-Key", "revoke-billing")];

    let (status, _headers, _problem) = answer(app, delete(&headers)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}
