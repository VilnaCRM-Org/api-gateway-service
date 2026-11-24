use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::policy_resync_fixtures::{Answers, OPERATION, Refusal, receipt, recorded, scenario};
use crate::principal::Principal;

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const RESYNC: &str = "mutation($input: ResyncPolicyInput!) { \
    resyncPolicy(input: $input) { id kind status totalRecords appliedRecords } }";

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
        Request::new(RESYNC).variables(Variables::from_json(json!({ "input": input })));
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
async fn a_resync_returns_the_bulk_operation_as_over_rest() {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "reason": "The topic lost records." }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "resyncPolicy": {
            "id": OPERATION,
            "kind": "resync",
            "status": "pending",
            "totalRecords": 2_500,
            "appliedRecords": 0,
        } })
    );
    let sent = recorded(&dispatched);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].reason, "The topic lost records.");
    assert!(sent[0].idempotency.is_none());
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_command() {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "reason": "again", "idempotencyKey": "resync-1" }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let sent = recorded(&dispatched);
    assert_eq!(
        sent[0].idempotency.as_ref().unwrap().key.as_str(),
        "resync-1"
    );
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_operation_without_a_command() {
    let (state, dispatched) = scenario(Answers {
        replay: Some(receipt()),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "reason": "again", "idempotencyKey": "resync-1" }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["resyncPolicy"]["id"], json!(OPERATION));
    assert!(recorded(&dispatched).is_empty());
}

#[rstest]
#[case::empty(json!({ "reason": "" }))]
#[case::blank(json!({ "reason": "   " }))]
#[case::missing(json!({}))]
#[case::two_lines(json!({ "reason": "first\nsecond" }))]
#[tokio::test]
async fn a_missing_or_unusable_reason_is_a_validation_failure_without_a_command(
    #[case] input: serde_json::Value,
) {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&dispatched).is_empty());
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_a_validation_failure() {
    let (state, dispatched) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "reason": "x", "idempotencyKey": "" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&dispatched).is_empty());
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
        let (state, _dispatched) = scenario(Answers {
            command: Err(refusal),
            ..Answers::default()
        });

        let response = run(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            json!({ "reason": "x" }),
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of(code)));
    }
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated_and_without_a_command() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, dispatched) = scenario(Answers::default());

        let response = run(&schema(Some(state)), caller, json!({ "reason": "x" })).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert!(recorded(&dispatched).is_empty());
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        json!({ "reason": "x" }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_prints_its_reason_and_key() {
    let input = super::ResyncPolicyInput {
        reason: "broker failure".to_owned(),
        idempotency_key: Some("resync-1".to_owned()),
    };

    let printed = format!("{input:?}");

    assert!(printed.contains("broker failure"));
    assert!(printed.contains("resync-1"));
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::InputType as _;

    use super::ResyncPolicyInput;

    let input = ResyncPolicyInput::parse(Some(
        Value::from_json(json!({ "reason": "broker failure", "idempotencyKey": "resync-1" }))
            .unwrap(),
    ))
    .unwrap();

    assert_eq!(input.reason, "broker failure");
    assert_eq!(input.idempotency_key.as_deref(), Some("resync-1"));
    assert!(ResyncPolicyInput::parse(Some(Value::Boolean(true))).is_err());
    let wrong_reason = json!({ "reason": true });
    let wrong_key = json!({ "reason": "broker failure", "idempotencyKey": true });
    assert!(ResyncPolicyInput::parse(Some(Value::from_json(wrong_reason).unwrap())).is_err());
    assert!(ResyncPolicyInput::parse(Some(Value::from_json(wrong_key).unwrap())).is_err());
}
