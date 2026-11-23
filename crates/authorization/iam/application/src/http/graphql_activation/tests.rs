use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::RequestDigester as _;
use serde_json::{Value, json};
use shared_application::http::Violation;
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::command::create_graphql_permissions::CreateGraphQlPermissionsCommand;
use crate::error::{Confirmation, IamError};
use crate::fixtures::principal;
use crate::graphql_activation_fixtures::{
    Answers, CREATED, Log, active_summary, receipt, recorded, scenario,
};
use crate::graphql_spec_fixtures::SPEC;
use crate::http::graphql_activation::dto::CreateGraphQlPermissionsRequest;
use crate::http::{IamState, router};

fn app(answers: Answers) -> (Router, Log<CreateGraphQlPermissionsCommand>) {
    let (state, commands) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), commands)
}

fn activate(id: &str, body: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("/graphql-specs/{id}/permissions"))
        .header(CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request.extensions_mut().insert(principal());
    request
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

#[tokio::test]
async fn a_draft_is_activated_with_201_its_created_keys_and_its_policy_version() {
    let (app, commands) = app(Answers::default());

    let (status, headers, body) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "7");
    assert_eq!(
        body,
        json!({
            "id": SPEC,
            "service": "billing",
            "status": "active",
            "createdKeys": [CREATED],
            "policyVersion": 7
        })
    );
    let dispatched = recorded(&commands);
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0].spec_id.to_string(), SPEC);
    assert!(!dispatched[0].confirm_orphans);
    assert!(!dispatched[0].confirm_flag_downgrade);
    assert_eq!(
        dispatched[0].renames,
        Vec::<(iam_domain::PermissionKey, iam_domain::PermissionKey)>::new()
    );
    assert!(dispatched[0].idempotency.is_none());
}

#[tokio::test]
async fn the_confirmations_and_the_renames_reach_the_command() {
    let (app, commands) = app(Answers::default());
    let body = json!({
        "confirmOrphans": true,
        "confirmFlagDowngrade": true,
        "renames": [{"from": "gql:billing:Query.bills", "to": CREATED}]
    })
    .to_string();

    let (status, ..) = answer(app, activate(SPEC, &body, None)).await;

    assert_eq!(status, StatusCode::CREATED);
    let dispatched = recorded(&commands);
    assert!(dispatched[0].confirm_orphans);
    assert!(dispatched[0].confirm_flag_downgrade);
    assert_eq!(dispatched[0].renames.len(), 1);
    assert_eq!(dispatched[0].renames[0].1.to_string(), CREATED);
}

#[tokio::test]
async fn the_idempotency_key_and_the_digest_of_the_request_reach_the_command() {
    let (app, commands) = app(Answers::default());

    let (status, ..) = answer(app, activate(SPEC, "{}", Some("activate-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    let idempotency = recorded(&commands)[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "activate-1");
    let expected = FakeRequestDigester.digest(
        &CreateGraphQlPermissionsRequest::default()
            .canonical_form(iam_domain::SpecId::parse(SPEC).unwrap()),
    );
    assert_eq!(idempotency.request_digest, expected);
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let (app, commands) = app(Answers {
        replay: Some(receipt(Some(5))),
        ..Answers::default()
    });

    let (status, headers, body) = answer(app, activate(SPEC, "{}", Some("activate-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "5");
    assert_eq!(body["policyVersion"], json!(5));
    assert_eq!(body["createdKeys"], json!([CREATED]));
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn a_replayed_receipt_without_a_policy_version_reports_the_current_one() {
    let (app, _commands) = app(Answers {
        replay: Some(receipt(None)),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(app, activate(SPEC, "{}", Some("activate-1"))).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["policyVersion"], json!(0));
}

#[tokio::test]
async fn an_active_version_is_200_with_no_created_keys_and_no_command() {
    let (app, commands) = app(Answers {
        spec: Ok(Some(active_summary())),
        ..Answers::default()
    });

    let (status, headers, body) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "0");
    assert_eq!(body["status"], json!("active"));
    assert_eq!(body["createdKeys"], json!([]));
    assert_eq!(body["policyVersion"], json!(0));
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn an_unknown_version_is_404() {
    let (app, commands) = app(Answers {
        spec: Ok(None),
        ..Answers::default()
    });

    let (status, ..) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn a_version_that_cannot_be_read_is_500_without_a_command() {
    let (app, commands) = app(Answers {
        spec: Err(|| IamError::Storage("database unavailable".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_a_422_violation_of_id() {
    let (app, _commands) = app(Answers::default());

    let (status, _headers, body) = answer(app, activate("nope", "{}", None)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
}

#[tokio::test]
async fn a_rename_that_is_not_a_key_is_a_422_violation_before_any_command() {
    let (app, commands) = app(Answers::default());
    let body = json!({"renames": [{"from": "nonsense", "to": CREATED}]}).to_string();

    let (status, _headers, body) = answer(app, activate(SPEC, &body, None)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("renames[0].from")
    );
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_a_422_violation() {
    let (app, _commands) = app(Answers::default());

    let (status, _headers, body) = answer(app, activate(SPEC, "{}", Some(""))).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("idempotencyKey")
    );
}

fn needs_flag_confirmation() -> IamError {
    IamError::ConfirmationRequired(
        Confirmation::FlagDowngrade,
        vec![Violation {
            property_path: "gql:billing:Mutation.pay".to_owned(),
            message: "This key would lose the sensitive or the always-audit flag.".to_owned(),
            code: "flag_downgrade".to_owned(),
        }],
    )
}

fn needs_orphan_confirmation() -> IamError {
    IamError::ConfirmationRequired(
        Confirmation::Orphans,
        vec![Violation {
            property_path: "gql:billing:Query.old".to_owned(),
            message: "The role 1 grants this key.".to_owned(),
            code: "orphaned_grant".to_owned(),
        }],
    )
}

#[tokio::test]
async fn a_missing_flag_confirmation_is_a_409_that_lists_the_keys() {
    let (app, _commands) = app(Answers {
        command: Err(needs_flag_confirmation),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["type"],
        json!("/problems/flag-downgrade-confirmation-required")
    );
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("gql:billing:Mutation.pay")
    );
}

#[tokio::test]
async fn a_missing_orphan_confirmation_is_a_409_that_lists_the_grants() {
    let (app, _commands) = app(Answers {
        command: Err(needs_orphan_confirmation),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["type"],
        json!("/problems/orphan-confirmation-required")
    );
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("gql:billing:Query.old")
    );
}

#[tokio::test]
async fn a_conflicting_change_is_a_409() {
    let (app, _commands) = app(Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    });

    let (status, ..) = answer(app, activate(SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_request_without_a_caller_is_401() {
    let (app, _commands) = app(Answers::default());
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/graphql-specs/{SPEC}/permissions"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let (status, ..) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
