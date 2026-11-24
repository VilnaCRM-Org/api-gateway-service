use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use serde_json::json;

use crate::command::revoke_sessions::RevokeSessionsCommand;
use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::revocation_fixtures::{Answers, Refusal, TARGET, receipt, recorded, scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const REVOKE: &str = "mutation($input: RevokeSessionsInput!) { \
    revokeSessions(input: $input) { id policyVersion } }";

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
    let mut request =
        Request::new(REVOKE).variables(Variables::from_json(json!({ "input": input })));
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
async fn a_revocation_returns_the_policy_version_as_over_rest() {
    let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER, "sessionIds": ["sid-1"] }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "revokeSessions": { "id": TARGET, "policyVersion": 41 } })
    );
    let sent = recorded(&dispatched);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user_id.to_string(), USER);
    assert_eq!(sent[0].session_ids.len(), 1);
}

#[tokio::test]
async fn a_missing_session_list_is_the_cutoff_of_the_user() {
    let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(recorded(&dispatched)[0].session_ids.len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_command_and_a_replay_sends_none() {
    let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER, "idempotencyKey": "revoke-1" }),
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
        "revoke-1"
    );
    let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let replayed = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER, "idempotencyKey": "revoke-1" }),
    )
    .await;

    assert!(replayed.errors.is_empty(), "{:?}", replayed.errors);
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn invalid_values_are_validation_failures_without_a_command() {
    let inputs = [
        json!({ "userId": "nobody" }),
        json!({ "userId": USER, "sessionIds": [""] }),
        json!({ "userId": USER, "idempotencyKey": "" }),
        json!({ "userId": USER, "consistency": "SOMETIMES" }),
    ];
    for input in inputs {
        let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers::default());

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
        let (state, _dispatched) = scenario::<RevokeSessionsCommand>(Answers {
            command: Err(refusal),
            ..Answers::default()
        });

        let response = run(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            json!({ "userId": USER }),
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of(code)));
    }
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated_and_without_a_command() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, dispatched) = scenario::<RevokeSessionsCommand>(Answers::default());

        let response = run(&schema(Some(state)), caller, json!({ "userId": USER })).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert!(recorded(&dispatched).is_empty());
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        json!({ "userId": USER }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::InputType as _;

    use super::RevokeSessionsInput;

    let input = RevokeSessionsInput::parse(Some(
        Value::from_json(json!({ "userId": USER, "sessionIds": ["sid-1"] })).unwrap(),
    ))
    .unwrap();

    assert_eq!(input.user_id.as_str(), USER);
    assert_eq!(input.session_ids, ["sid-1"]);
    assert!(input.idempotency_key.is_none());
    assert!(RevokeSessionsInput::parse(Some(Value::Boolean(true))).is_err());
    for wrong in [
        json!({ "userId": true }),
        json!({ "sessionIds": ["sid-1"] }),
        json!({ "userId": USER, "sessionIds": true }),
        json!({ "userId": USER, "idempotencyKey": true }),
        json!({ "userId": USER, "consistency": true }),
    ] {
        assert!(RevokeSessionsInput::parse(Some(Value::from_json(wrong).unwrap())).is_err());
    }
    assert!(RevokeSessionsInput::parse(None).is_err());
}
