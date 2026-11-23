use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::RequestDigester as _;
use rstest::rstest;
use serde_json::{Value, json};
use shared_application::http::Violation;
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::error::{Confirmation, IamError};
use crate::fixtures::principal;
use crate::graphql_spec_fixtures::SPEC;
use crate::http::spec_retirement::dto::RetireSpecRequest;
use crate::http::{IamState, router};
use crate::spec_retirement_fixtures::{Answers, Dispatched, receipt, recorded, scenario};

fn app(answers: Answers) -> (Router, Dispatched) {
    let (state, dispatched) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), dispatched)
}

fn retire(form: &str, id: &str, body: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("/{form}-specs/{id}/retirement"))
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
async fn a_graphql_version_is_retired_with_200_and_its_policy_version() {
    let (app, dispatched) = app(Answers::default());

    let (status, headers, body) = answer(app, retire("graphql", SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "7");
    assert_eq!(
        body,
        json!({
            "id": SPEC,
            "service": "billing",
            "status": "retired",
            "policyVersion": 7
        })
    );
    let sent = recorded(&dispatched.graphql);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].spec_id.to_string(), SPEC);
    assert!(!sent[0].confirm_orphans);
    assert!(sent[0].idempotency.is_none());
    assert!(recorded(&dispatched.openapi).is_empty());
}

#[tokio::test]
async fn an_openapi_version_is_retired_with_200_and_its_policy_version() {
    let (app, dispatched) = app(Answers {
        target_type: "openapi_spec",
        ..Answers::default()
    });

    let (status, headers, body) = answer(app, retire("openapi", SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "7");
    assert_eq!(body["status"], json!("retired"));
    assert_eq!(body["service"], json!("billing"));
    assert_eq!(recorded(&dispatched.openapi).len(), 1);
    assert!(recorded(&dispatched.graphql).is_empty());
}

#[rstest]
#[case::graphql("graphql", "graphql_spec")]
#[case::openapi("openapi", "openapi_spec")]
#[tokio::test]
async fn the_confirmation_and_the_idempotency_key_reach_the_command(
    #[case] form: &str,
    #[case] target_type: &'static str,
) {
    let (app, dispatched) = app(Answers {
        target_type,
        ..Answers::default()
    });

    let (status, ..) = answer(
        app,
        retire(form, SPEC, r#"{"confirmOrphans": true}"#, Some("retire-1")),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let (confirmed, idempotency) = if form == "graphql" {
        let sent = recorded(&dispatched.graphql);
        (sent[0].confirm_orphans, sent[0].idempotency.clone())
    } else {
        let sent = recorded(&dispatched.openapi);
        (sent[0].confirm_orphans, sent[0].idempotency.clone())
    };
    assert!(confirmed);
    let idempotency = idempotency.unwrap();
    assert_eq!(idempotency.key.as_str(), "retire-1");
    let request = RetireSpecRequest {
        confirm_orphans: true,
    };
    let operation = if form == "graphql" {
        "graphql_spec"
    } else {
        "openapi_spec"
    };
    let expected = FakeRequestDigester
        .digest(&request.canonical_form(operation, iam_domain::SpecId::parse(SPEC).unwrap()));
    assert_eq!(idempotency.request_digest, expected);
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let (app, dispatched) = app(Answers {
        replay: Some(receipt("graphql_spec", Some(5))),
        ..Answers::default()
    });

    let (status, headers, body) =
        answer(app, retire("graphql", SPEC, "{}", Some("retire-1"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("iam-policy-version").unwrap(), "5");
    assert_eq!(body["policyVersion"], json!(5));
    assert_eq!(body["status"], json!("retired"));
    assert!(recorded(&dispatched.graphql).is_empty());
}

#[tokio::test]
async fn a_replayed_receipt_without_a_policy_version_reports_the_current_one() {
    let (app, _dispatched) = app(Answers {
        replay: Some(receipt("openapi_spec", None)),
        ..Answers::default()
    });

    let (status, _headers, body) =
        answer(app, retire("openapi", SPEC, "{}", Some("retire-1"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policyVersion"], json!(0));
}

#[rstest]
#[case::graphql("graphql")]
#[case::openapi("openapi")]
#[tokio::test]
async fn an_unknown_version_is_404_without_a_command(#[case] form: &str) {
    let (app, dispatched) = app(Answers {
        graphql: Ok(None),
        openapi: Ok(None),
        ..Answers::default()
    });

    let (status, ..) = answer(app, retire(form, SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(recorded(&dispatched.graphql).is_empty());
    assert!(recorded(&dispatched.openapi).is_empty());
}

#[rstest]
#[case::graphql("graphql")]
#[case::openapi("openapi")]
#[tokio::test]
async fn a_version_that_cannot_be_read_is_500_without_a_command(#[case] form: &str) {
    let (app, dispatched) = app(Answers {
        graphql: Err(|| IamError::Storage("database unavailable".into())),
        openapi: Err(|| IamError::Storage("database unavailable".into())),
        ..Answers::default()
    });

    let (status, ..) = answer(app, retire(form, SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(recorded(&dispatched.graphql).is_empty());
    assert!(recorded(&dispatched.openapi).is_empty());
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_a_422_violation_of_id() {
    let (app, _dispatched) = app(Answers::default());

    let (status, _headers, body) = answer(app, retire("graphql", "nope", "{}", None)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_a_422_violation() {
    let (app, _dispatched) = app(Answers::default());

    let (status, _headers, body) = answer(app, retire("openapi", SPEC, "{}", Some(""))).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("idempotencyKey")
    );
}

#[tokio::test]
async fn an_unknown_body_field_is_refused() {
    let (app, dispatched) = app(Answers::default());

    let (status, ..) = answer(
        app,
        retire("graphql", SPEC, r#"{"confirmFlagDowngrade": true}"#, None),
    )
    .await;

    assert!(status.is_client_error());
    assert!(recorded(&dispatched.graphql).is_empty());
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

#[rstest]
#[case::graphql("graphql")]
#[case::openapi("openapi")]
#[tokio::test]
async fn a_missing_orphan_confirmation_is_a_409_that_lists_the_grants(#[case] form: &str) {
    let (app, _dispatched) = app(Answers {
        command: Err(needs_orphan_confirmation),
        ..Answers::default()
    });

    let (status, _headers, body) = answer(app, retire(form, SPEC, "{}", None)).await;

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
async fn a_version_that_is_not_active_or_a_concurrent_change_is_a_409() {
    let (app, _dispatched) = app(Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    });

    let (status, ..) = answer(app, retire("graphql", SPEC, "{}", None)).await;

    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_request_without_a_caller_is_401() {
    let (app, _dispatched) = app(Answers::default());
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/openapi-specs/{SPEC}/retirement"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let (status, ..) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
