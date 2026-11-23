use async_graphql::{EmptySubscription, InputType as _, Name, Request, Schema, Value, Variables};
use rstest::rstest;
use serde_json::json;
use shared_application::http::Violation;

use crate::error::{Confirmation, IamError};
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::graphql_spec_fixtures::SPEC;
use crate::http::IamState;
use crate::principal::Principal;
use crate::spec_retirement_fixtures::{Answers, receipt, recorded, scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const GRAPHQL: &str = "mutation($input: RetireGraphqlSpecInput!) { \
    retireGraphqlSpec(input: $input) { id service status policyVersion } }";
const OPENAPI: &str = "mutation($input: RetireOpenapiSpecInput!) { \
    retireOpenapiSpec(input: $input) { id service status policyVersion } }";

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

async fn run(
    schema: &IamSchema,
    document: &str,
    caller: Caller,
    input: serde_json::Value,
) -> async_graphql::Response {
    let mut request =
        Request::new(document).variables(Variables::from_json(json!({ "input": input })));
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

#[tokio::test]
async fn a_graphql_retirement_returns_the_same_data_as_over_rest() {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        GRAPHQL,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "retireGraphqlSpec": {
            "id": SPEC,
            "service": "billing",
            "status": "retired",
            "policyVersion": 7,
        } })
    );
    let sent = recorded(&dispatched.graphql);
    assert_eq!(sent.len(), 1);
    assert!(!sent[0].confirm_orphans);
    assert!(sent[0].idempotency.is_none());
}

#[tokio::test]
async fn an_openapi_retirement_returns_the_same_data_as_over_rest() {
    let (state, dispatched) = scenario(Answers {
        target_type: "openapi_spec",
        ..Answers::default()
    });
    let input = json!({ "id": SPEC, "confirmOrphans": true, "idempotencyKey": "retire-1" });

    let response = run(
        &schema(Some(state)),
        OPENAPI,
        Caller::Data(Some(principal())),
        input,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "retireOpenapiSpec": {
            "id": SPEC,
            "service": "billing",
            "status": "retired",
            "policyVersion": 7,
        } })
    );
    let sent = recorded(&dispatched.openapi);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].confirm_orphans);
    assert_eq!(
        sent[0].idempotency.as_ref().unwrap().key.as_str(),
        "retire-1"
    );
}

#[tokio::test]
async fn the_confirmation_and_the_idempotency_key_reach_the_graphql_command() {
    let (state, dispatched) = scenario(Answers::default());
    let input = json!({ "id": SPEC, "confirmOrphans": true, "idempotencyKey": "retire-1" });

    let response = run(
        &schema(Some(state)),
        GRAPHQL,
        Caller::Data(Some(principal())),
        input,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let sent = recorded(&dispatched.graphql);
    assert!(sent[0].confirm_orphans);
    assert_eq!(
        sent[0].idempotency.as_ref().unwrap().key.as_str(),
        "retire-1"
    );
}

#[rstest]
#[case::graphql(GRAPHQL, "retireGraphqlSpec")]
#[case::openapi(OPENAPI, "retireOpenapiSpec")]
#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command(
    #[case] document: &str,
    #[case] field: &str,
) {
    let (state, dispatched) = scenario(Answers {
        replay: Some(receipt("graphql_spec", Some(5))),
        ..Answers::default()
    });
    let input = json!({ "id": SPEC, "idempotencyKey": "retire-1" });

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        input,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data[field]["policyVersion"], json!(5));
    assert!(recorded(&dispatched.graphql).is_empty());
    assert!(recorded(&dispatched.openapi).is_empty());
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn a_missing_orphan_confirmation_is_its_own_error_code(#[case] document: &str) {
    let (state, _dispatched) = scenario(Answers {
        command: Err(|| {
            IamError::ConfirmationRequired(
                Confirmation::Orphans,
                vec![Violation {
                    property_path: "gql:billing:Query.old".to_owned(),
                    message: "The role 1 grants this key.".to_owned(),
                    code: "orphaned_grant".to_owned(),
                }],
            )
        }),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("ORPHAN_CONFIRMATION_REQUIRED"))
    );
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn a_version_that_is_not_active_is_a_conflict(#[case] document: &str) {
    let (state, _dispatched) = scenario(Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("CONFLICT")));
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn an_unknown_version_is_not_found(#[case] document: &str) {
    let (state, _dispatched) = scenario(Answers {
        graphql: Ok(None),
        openapi: Ok(None),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("NOT_FOUND")));
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn an_id_that_is_not_a_uuid_fails_validation(#[case] document: &str) {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": "nope" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&dispatched.graphql).is_empty());
    assert!(recorded(&dispatched.openapi).is_empty());
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn a_malformed_idempotency_key_fails_validation(#[case] document: &str) {
    let (state, _dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC, "idempotencyKey": "" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated(#[case] document: &str) {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, _dispatched) = scenario(Answers::default());

        let response = run(
            &schema(Some(state)),
            document,
            caller,
            json!({ "id": SPEC }),
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    }
}

#[rstest]
#[case::graphql(GRAPHQL)]
#[case::openapi(OPENAPI)]
#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error(#[case] document: &str) {
    let response = run(
        &schema(None),
        document,
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_retirement_inputs_print_their_fields() {
    let graphql = super::RetireGraphQlSpecInput {
        id: async_graphql::ID::from(SPEC),
        confirm_orphans: true,
        idempotency_key: None,
    };
    let openapi = super::RetireOpenApiSpecInput {
        id: async_graphql::ID::from(SPEC),
        confirm_orphans: false,
        idempotency_key: Some("retire-1".to_owned()),
    };

    assert_eq!(
        format!("{graphql:?}"),
        format!(
            "RetireGraphQlSpecInput {{ id: ID(\"{SPEC}\"), confirm_orphans: true, \
             idempotency_key: None }}"
        )
    );
    assert_eq!(
        format!("{openapi:?}"),
        format!(
            "RetireOpenApiSpecInput {{ id: ID(\"{SPEC}\"), confirm_orphans: false, \
             idempotency_key: Some(\"retire-1\") }}"
        )
    );
}

fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (Name::new(name), value))
            .collect(),
    )
}

#[test]
fn the_retirement_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    let input = object(vec![
        ("id", Value::String(SPEC.to_owned())),
        ("confirmOrphans", Value::Boolean(true)),
    ]);

    let graphql = super::RetireGraphQlSpecInput::parse(Some(input.clone())).unwrap();
    let openapi = super::RetireOpenApiSpecInput::parse(Some(input)).unwrap();

    assert_eq!(graphql.id.as_str(), SPEC);
    assert!(graphql.confirm_orphans);
    assert_eq!(graphql.idempotency_key, None);
    assert_eq!(openapi.id.as_str(), SPEC);
    assert!(openapi.confirm_orphans);
    assert!(super::RetireGraphQlSpecInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(super::RetireOpenApiSpecInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["id", "confirmOrphans", "idempotencyKey"] {
        let wrong = object(vec![
            ("id", Value::String(SPEC.to_owned())),
            (field, Value::Enum(Name::new("WRONG"))),
        ]);
        assert!(
            super::RetireGraphQlSpecInput::parse(Some(wrong.clone())).is_err(),
            "{field}"
        );
        assert!(
            super::RetireOpenApiSpecInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
