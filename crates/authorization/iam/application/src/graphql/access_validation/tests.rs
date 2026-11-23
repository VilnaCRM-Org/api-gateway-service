use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{AccessTarget, DecisionReason, HttpMethod};
use serde_json::json;

use crate::access_validation_fixtures::{
    DECISION, PROJECT, SUBJECT, allowed, allowed_in_project, denied, recorded, scenario,
    token_refused,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const VALIDATE: &str = "query($input: ValidateAccessInput!) { validateAccess(input: $input) \
    { decision reason denied scopes { all projects } subject { id kind } decisionId \
    policyVersion requestId } }";

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, IamMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Data(Option<Principal>),
}

async fn validate(
    schema: &IamSchema,
    caller: Caller,
    input: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(VALIDATE).variables(Variables::from_json(json!({
        "input": input
    })));
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    schema.execute(request).await
}

fn error_code(response: &async_graphql::Response) -> Option<Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

fn rest_input() -> serde_json::Value {
    json!({
        "credential": "subject-token",
        "service": "billing",
        "rest": {"method": "GET", "path": "/api/invoices/42"},
        "requestId": "req-1"
    })
}

#[tokio::test]
async fn an_allowed_check_is_a_decision_that_echoes_the_request_id() {
    let (state, asked) = scenario(Ok(allowed()));

    let response = validate(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        rest_input(),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "validateAccess": {
            "decision": "allow",
            "reason": "allowed",
            "denied": [],
            "scopes": {"all": true, "projects": []},
            "subject": {"id": SUBJECT, "kind": "user"},
            "decisionId": DECISION,
            "policyVersion": 7,
            "requestId": "req-1",
        } })
    );
    let [query] = recorded(&asked).try_into().unwrap();
    assert_eq!(query.credential.expose(), "subject-token");
    let AccessTarget::Rest(target) = query.check.target() else {
        panic!("expected a REST target");
    };
    assert_eq!(target.method(), HttpMethod::Get);
    assert_eq!(target.path(), "/api/invoices/42");
}

#[tokio::test]
async fn an_allow_in_one_project_lists_the_project_ids() {
    let (state, asked) = scenario(Ok(allowed_in_project()));
    let input = json!({
        "credential": "subject-token", "service": "billing", "requestId": "req-2",
        "permissions": ["rest:billing:GET /api/invoices"],
        "projectId": PROJECT, "minPolicyVersion": 7
    });

    let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap()["validateAccess"]["scopes"],
        json!({"all": false, "projects": [PROJECT]})
    );
    let [query] = recorded(&asked).try_into().unwrap();
    assert_eq!(query.check.project().unwrap().to_string(), PROJECT);
    assert_eq!(query.check.min_policy_version().unwrap().value(), 7);
}

#[tokio::test]
async fn a_denied_check_is_a_decision_with_the_reason_and_the_denied_keys() {
    let outcome = denied(
        DecisionReason::PermissionMissing,
        &["rest:billing:GET /api/invoices/{}"],
    );
    let (state, _asked) = scenario(Ok(outcome));

    let response = validate(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        rest_input(),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["validateAccess"]["decision"], json!("deny"));
    assert_eq!(
        data["validateAccess"]["reason"],
        json!("permission_missing")
    );
    assert_eq!(
        data["validateAccess"]["denied"],
        json!(["rest:billing:GET /api/invoices/{}"])
    );
    assert_eq!(
        data["validateAccess"]["scopes"],
        json!({"all": false, "projects": []})
    );
}

#[tokio::test]
async fn a_graphql_document_is_asked_with_its_operation_name() {
    let (state, asked) = scenario(Ok(allowed()));
    let input = json!({
        "credential": "subject-token", "service": "billing", "requestId": "req-doc",
        "graphql": {"document": "query Get { invoice { id } }", "operationName": "Get"}
    });

    let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let [query] = recorded(&asked).try_into().unwrap();
    let AccessTarget::GraphQl(target) = query.check.target() else {
        panic!("expected a GraphQL target");
    };
    assert_eq!(target.document(), "query Get { invoice { id } }");
    assert_eq!(target.operation_name(), Some("Get"));
}

#[tokio::test]
async fn a_denied_document_lists_every_denied_coordinate() {
    let outcome = denied(
        DecisionReason::PermissionMissing,
        &["gql:billing:Invoice.total", "gql:billing:Query.invoice"],
    );
    let (state, _asked) = scenario(Ok(outcome));
    let input = json!({
        "credential": "subject-token", "service": "billing", "requestId": "req-doc",
        "graphql": {"document": "{ invoice { total } }"}
    });

    let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    let data = response.data.into_json().unwrap();
    assert_eq!(data["validateAccess"]["decision"], json!("deny"));
    assert_eq!(
        data["validateAccess"]["denied"],
        json!(["gql:billing:Invoice.total", "gql:billing:Query.invoice"])
    );
}

#[tokio::test]
async fn a_graphql_target_beside_a_rest_target_is_validation_failed_and_asks_nothing() {
    let (state, asked) = scenario(Ok(allowed()));
    let input = json!({
        "credential": "t", "service": "billing", "requestId": "r",
        "rest": {"method": "GET", "path": "/"}, "graphql": {"document": "{ a }"}
    });

    let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(recorded(&asked).len(), 0);
}

#[tokio::test]
async fn a_refused_token_has_no_subject_and_no_policy_version() {
    let (state, _asked) = scenario(Ok(token_refused()));

    let response = validate(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        rest_input(),
    )
    .await;

    let data = response.data.into_json().unwrap();
    assert_eq!(data["validateAccess"]["reason"], json!("token_expired"));
    assert_eq!(data["validateAccess"]["subject"], json!(null));
    assert_eq!(data["validateAccess"]["policyVersion"], json!(null));
}

#[tokio::test]
async fn a_request_with_no_target_or_two_targets_is_validation_failed_and_asks_nothing() {
    let none = json!({"credential": "t", "service": "billing", "requestId": "r"});
    let two = json!({
        "credential": "t", "service": "billing", "requestId": "r",
        "rest": {"method": "GET", "path": "/"}, "permissions": ["iam:validate:*"]
    });
    for input in [none, two] {
        let (state, asked) = scenario(Ok(allowed()));

        let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

        assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
        assert_eq!(recorded(&asked).len(), 0);
    }
}

#[tokio::test]
async fn more_than_one_hundred_keys_are_validation_failed() {
    let keys: Vec<String> = (0..101)
        .map(|index| format!("rest:billing:GET /api/invoices/{index}"))
        .collect();
    let input = json!({
        "credential": "t", "service": "billing", "requestId": "r", "permissions": keys
    });
    let (state, asked) = scenario(Ok(allowed()));

    let response = validate(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(recorded(&asked).len(), 0);
}

#[tokio::test]
async fn a_minimum_version_that_the_handler_refuses_is_validation_failed() {
    let (state, _asked) = scenario(Err(|| {
        IamError::invalid_property("minPolicyVersion", "Too new.", "range")
    }));

    let response = validate(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        rest_input(),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_storage_failure_of_the_bus_is_an_internal_error() {
    let (state, _asked) = scenario(Err(|| IamError::Storage("down".into())));

    let response = validate(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        rest_input(),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, asked) = scenario(Ok(allowed()));

        let response = validate(&schema(Some(state)), caller, rest_input()).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert_eq!(recorded(&asked).len(), 0);
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = validate(&schema(None), Caller::Data(Some(principal())), rest_input()).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_does_not_print_the_credential() {
    let input: super::ValidateAccessInput = super::ValidateAccessInput {
        credential: "raw-secret-token".to_owned(),
        service: "billing".to_owned(),
        rest: None,
        graphql: None,
        permissions: None,
        project_id: None,
        min_policy_version: None,
        request_id: "r".to_owned(),
    };

    assert!(!format!("{input:?}").contains("raw-secret-token"));
}

#[test]
fn the_inputs_are_read_from_a_graphql_object_and_a_wrong_last_field_is_refused() {
    use async_graphql::{InputType as _, Name};

    use super::{AccessRestTargetInput, ValidateAccessInput};

    let object = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };
    let rest = object(vec![
        ("method", Value::String("GET".to_owned())),
        ("path", Value::String("/api/invoices".to_owned())),
    ]);
    let input = |rest: Value, request_id: Value| {
        object(vec![
            ("credential", Value::String("token".to_owned())),
            ("service", Value::String("billing".to_owned())),
            ("rest", rest),
            ("requestId", request_id),
        ])
    };

    let target = AccessRestTargetInput::parse(Some(rest.clone())).unwrap();
    let parsed =
        ValidateAccessInput::parse(Some(input(rest, Value::String("r-1".to_owned())))).unwrap();
    let wrong_path = object(vec![
        ("method", Value::String("GET".to_owned())),
        ("path", Value::List(Vec::new())),
    ]);

    assert_eq!(target.method, "GET");
    assert_eq!(target.path, "/api/invoices");
    assert_eq!(parsed.service, "billing");
    assert_eq!(parsed.request_id, "r-1");
    assert_eq!(parsed.rest.unwrap().path, "/api/invoices");
    assert!(parsed.permissions.is_none());
    assert!(AccessRestTargetInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(ValidateAccessInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(AccessRestTargetInput::parse(Some(wrong_path)).is_err());
    assert!(ValidateAccessInput::parse(Some(input(Value::Null, Value::List(Vec::new())))).is_err());
}

#[test]
fn the_graphql_target_is_read_from_a_graphql_object_and_printed_with_its_document() {
    use async_graphql::{InputType as _, Name};

    use super::AccessGraphQlTargetInput;

    let graphql = Value::Object(
        [
            (
                Name::new("document"),
                Value::String("{ invoice { id } }".to_owned()),
            ),
            (Name::new("operationName"), Value::Null),
        ]
        .into_iter()
        .collect(),
    );

    let target = AccessGraphQlTargetInput::parse(Some(graphql)).unwrap();

    assert_eq!(target.document, "{ invoice { id } }");
    assert!(target.operation_name.is_none());
    assert!(format!("{target:?}").contains("{ invoice { id } }"));
    let wrong_document =
        Value::Object(std::iter::once((Name::new("document"), Value::List(Vec::new()))).collect());
    let wrong_operation = Value::Object(
        [
            (
                Name::new("document"),
                Value::String("{ invoice { id } }".to_owned()),
            ),
            (Name::new("operationName"), Value::List(Vec::new())),
        ]
        .into_iter()
        .collect(),
    );

    assert!(AccessGraphQlTargetInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(AccessGraphQlTargetInput::parse(Some(wrong_document)).is_err());
    assert!(AccessGraphQlTargetInput::parse(Some(wrong_operation)).is_err());
}
