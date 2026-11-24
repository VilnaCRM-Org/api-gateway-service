use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use serde_json::json;

use crate::command::set_global_token_cutoff::SetGlobalTokenCutoffCommand;
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::revocation_fixtures::{Answers, Refusal, TARGET, receipt, recorded, scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const SET: &str = "mutation($input: SetGlobalTokenCutoffInput!) { \
    setGlobalTokenCutoff(input: $input) { id policyVersion } }";

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
    input: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(SET).variables(Variables::from_json(json!({ "input": input })));
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
async fn the_cutoff_returns_the_policy_version_as_over_rest() {
    let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "setGlobalTokenCutoff": { "id": TARGET, "policyVersion": 41 } })
    );
    assert_eq!(recorded(&dispatched).len(), 1);
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_command_and_a_replay_sends_none() {
    let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "idempotencyKey": "cutoff-1" }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&dispatched)[0]
            .idempotency
            .as_ref()
            .unwrap()
            .key
            .as_str(),
        "cutoff-1"
    );
    let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let replayed = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "idempotencyKey": "cutoff-1" }),
    )
    .await;

    assert!(replayed.errors.is_empty(), "{:?}", replayed.errors);
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_malformed_key_or_consistency_is_a_validation_failure_without_a_command() {
    for input in [
        json!({ "idempotencyKey": "" }),
        json!({ "consistency": "SOMETIMES" }),
    ] {
        let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers::default());

        let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

        assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
        assert!(recorded(&dispatched).is_empty());
    }
}

#[tokio::test]
async fn a_refused_command_is_its_error_code() {
    let refusals: [(Refusal, &str); 2] = [
        (|| IamError::Conflict, "CONFLICT"),
        (
            || IamError::Storage("database unavailable".into()),
            "INTERNAL_SERVER_ERROR",
        ),
    ];
    for (refusal, code) in refusals {
        let (state, _dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers {
            command: Err(refusal),
            ..Answers::default()
        });

        let response = run(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            json!({}),
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of(code)));
    }
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated_and_without_a_command() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, dispatched) = scenario::<SetGlobalTokenCutoffCommand>(Answers::default());

        let response = run(&schema(Some(state)), caller, json!({})).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert!(recorded(&dispatched).is_empty());
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Data(Some(principal())), json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::InputType as _;

    use super::SetGlobalTokenCutoffInput;

    let input = SetGlobalTokenCutoffInput::parse(Some(
        Value::from_json(json!({ "idempotencyKey": "cutoff-1", "consistency": "PUBLISHED" }))
            .unwrap(),
    ))
    .unwrap();

    assert_eq!(input.idempotency_key.as_deref(), Some("cutoff-1"));
    assert_eq!(input.consistency.as_deref(), Some("PUBLISHED"));
    assert!(SetGlobalTokenCutoffInput::parse(Some(Value::Boolean(true))).is_err());
    for wrong in [
        json!({ "idempotencyKey": true }),
        json!({ "consistency": true }),
    ] {
        assert!(SetGlobalTokenCutoffInput::parse(Some(Value::from_json(wrong).unwrap())).is_err());
    }
    assert!(SetGlobalTokenCutoffInput::parse(None).is_err());
    let empty =
        SetGlobalTokenCutoffInput::parse(Some(Value::from_json(json!({})).unwrap())).unwrap();
    assert!(empty.idempotency_key.is_none() && empty.consistency.is_none());
}
