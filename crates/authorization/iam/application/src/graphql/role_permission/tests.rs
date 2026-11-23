use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use serde_json::json;
use shared_application::http::Violation;

use crate::error::IamError;
use crate::fixtures::{ROLE, principal};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::role_permission_fixtures::{Answers, recorded, scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const SET: &str = "mutation($input: SetRolePermissionsInput!) { \
    setRolePermissions(input: $input) { id version grantCount \
    permissions { key kind service active wildcard } } }";

const READ: &str =
    "query($id: ID!) { role(id: $id) { id permissions { key kind service active wildcard } } }";

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
    caller: Caller,
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    schema.execute(request).await
}

fn set(input: &serde_json::Value) -> serde_json::Value {
    json!({ "input": input })
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

fn grants_json() -> serde_json::Value {
    json!([
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
    ])
}

#[tokio::test]
async fn a_replacement_returns_the_role_with_its_grants_as_over_rest() {
    let (state, _commands, _queries, sent, _replays) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({
            "id": ROLE,
            "expectedVersion": 1,
            "keys": ["gql:billing:*", "rest:billing:GET /invoices"],
        })),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "setRolePermissions": {
            "id": ROLE,
            "version": 2,
            "grantCount": 0,
            "permissions": grants_json(),
        } })
    );
    let dispatched = recorded(&sent);
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0].expected.value(), 1);
    assert_eq!(
        dispatched[0].keys,
        ["gql:billing:*", "rest:billing:GET /invoices"]
    );
    assert!(dispatched[0].idempotency.is_none());
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_command() {
    let (state, _commands, _queries, sent, _replays) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({
            "id": ROLE,
            "expectedVersion": 1,
            "keys": [],
            "idempotencyKey": "grants-1",
        })),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let idempotency = recorded(&sent)[0].idempotency.clone().unwrap();
    assert_eq!(idempotency.key.as_str(), "grants-1");
}

#[tokio::test]
async fn the_grants_of_a_role_are_a_field_of_the_role() {
    let (state, ..) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        READ,
        json!({ "id": ROLE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "role": { "id": ROLE, "permissions": grants_json() } })
    );
}

#[tokio::test]
async fn a_missing_expected_version_is_precondition_required_and_a_stale_one_precondition_failed() {
    let (state, ..) = scenario(Answers::default());
    let schema = schema(Some(state));
    let caller = || Caller::Data(Some(principal()));

    let missing = run(
        &schema,
        caller(),
        SET,
        set(&json!({ "id": ROLE, "keys": [] })),
    )
    .await;
    let invalid = run(
        &schema,
        caller(),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 0, "keys": [] })),
    )
    .await;

    assert_eq!(error_code(&missing), Some(code_of("PRECONDITION_REQUIRED")));
    assert_eq!(error_code(&invalid), Some(code_of("PRECONDITION_FAILED")));
}

#[tokio::test]
async fn a_stale_version_from_the_command_is_precondition_failed() {
    let (state, ..) = scenario(Answers {
        command: Err(|| IamError::PreconditionFailed),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("PRECONDITION_FAILED")));
}

#[tokio::test]
async fn unknown_keys_fail_with_validation_failed_and_one_violation_each() {
    let (state, ..) = scenario(Answers {
        command: Err(|| {
            IamError::Invalid(vec![Violation {
                property_path: "keys[1]".to_owned(),
                message: "unknown".to_owned(),
                code: "exists".to_owned(),
            }])
        }),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": ["a", "b"] })),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn more_than_five_thousand_keys_fail_with_validation_failed_before_any_command() {
    let (state, commands, ..) = scenario(Answers::default());
    let keys: Vec<String> = (0..=5_000)
        .map(|n| format!("rest:billing:GET /a{n}"))
        .collect();

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": keys })),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_fails_with_validation_failed() {
    let (state, ..) = scenario(Answers::default());
    let schema = schema(Some(state));

    let set_response = run(
        &schema,
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": "nope", "expectedVersion": 1, "keys": [] })),
    )
    .await;
    let read_response = run(
        &schema,
        Caller::Data(Some(principal())),
        READ,
        json!({ "id": "nope" }),
    )
    .await;

    assert_eq!(
        error_code(&set_response),
        Some(code_of("VALIDATION_FAILED"))
    );
    assert_eq!(
        error_code(&read_response),
        Some(code_of("VALIDATION_FAILED"))
    );
}

#[tokio::test]
async fn a_role_that_vanishes_is_not_found() {
    let (state, ..) = scenario(Answers {
        permissions: Ok(None),
        ..Answers::default()
    });
    let schema = schema(Some(state));

    let set_response = run(
        &schema,
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;
    let read_response = run(
        &schema,
        Caller::Data(Some(principal())),
        READ,
        json!({ "id": ROLE }),
    )
    .await;

    assert_eq!(error_code(&set_response), Some(code_of("NOT_FOUND")));
    assert_eq!(error_code(&read_response), Some(code_of("NOT_FOUND")));
}

#[tokio::test]
async fn a_role_that_cannot_be_read_back_after_the_commit_is_not_found() {
    let (state, ..) = scenario(Answers {
        role: Ok(None),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("NOT_FOUND")));
}

#[tokio::test]
async fn an_unauthenticated_caller_is_refused() {
    let (state, commands, ..) = scenario(Answers::default());
    let schema = schema(Some(state));

    let no_caller = run(
        &schema,
        Caller::Data(None),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;
    let no_data = run(&schema, Caller::Absent, READ, json!({ "id": ROLE })).await;

    assert_eq!(error_code(&no_caller), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(error_code(&no_data), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_schema_without_the_state_fails_the_request() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn a_role_that_fails_to_be_read_back_after_the_commit_is_a_server_error() {
    let (state, ..) = scenario(Answers {
        role: Err(|| IamError::Storage("down".into())),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        SET,
        set(&json!({ "id": ROLE, "expectedVersion": 1, "keys": [] })),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    use super::SetRolePermissionsInput;

    let input = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };

    let parsed = SetRolePermissionsInput::parse(Some(input(vec![
        ("id", Value::String(ROLE.to_owned())),
        ("expectedVersion", Value::Number(3.into())),
        (
            "keys",
            Value::List(vec![Value::String("gql:billing:*".to_owned())]),
        ),
        ("idempotencyKey", Value::String("grants-1".to_owned())),
    ])))
    .unwrap();

    assert_eq!(parsed.id.as_str(), ROLE);
    assert_eq!(parsed.expected_version, Some(3));
    assert_eq!(parsed.keys, ["gql:billing:*"]);
    assert_eq!(parsed.idempotency_key.as_deref(), Some("grants-1"));
    assert!(SetRolePermissionsInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["id", "expectedVersion", "keys", "idempotencyKey"] {
        let wrong = input(vec![
            ("id", Value::String(ROLE.to_owned())),
            ("keys", Value::List(Vec::new())),
            (field, Value::Boolean(false)),
        ]);
        assert!(
            SetRolePermissionsInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
