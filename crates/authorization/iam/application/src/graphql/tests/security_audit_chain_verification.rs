use std::sync::PoisonError;

use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{ChainBreak, ChainBreakCause, ChainVerification, SecurityAuditEventId};
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery, SecurityAuditAnchorInput};
use crate::http::IamState;
use crate::principal::Principal;
use crate::security_audit_fixtures::{uuid, verification_scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const HASH: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

const VERIFY: &str = "query($anchors: [SecurityAuditAnchorInput!]) \
    { securityAuditChainVerification(anchors: $anchors) \
    { status recordsChecked invalidRecordId invalidSeq cause } }";

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, IamMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// Whether the request carries a caller.
enum Caller {
    Absent,
    Refused,
    Valid,
}

async fn run(
    schema: &IamSchema,
    caller: Caller,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(VERIFY).variables(Variables::from_json(variables));
    match caller {
        Caller::Absent => {}
        Caller::Refused => request = request.data(None::<Principal>),
        Caller::Valid => request = request.data(Some(principal())),
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

#[tokio::test]
async fn a_valid_chain_is_verified_with_the_number_of_records_checked() {
    let (state, verified) = verification_scenario(Ok(ChainVerification::valid(8)));

    let response = run(&schema(Some(state)), Caller::Valid, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "securityAuditChainVerification": {
            "status": "valid",
            "recordsChecked": 8,
            "invalidRecordId": null,
            "invalidSeq": null,
            "cause": null,
        } })
    );
    let asked = verified.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].anchors, Vec::new());
    drop(asked);
}

#[tokio::test]
async fn a_broken_chain_names_the_record_its_place_and_the_cause() {
    let id = SecurityAuditEventId::from_uuid(uuid(2));
    let broken = ChainBreak::new(2, Some(id), ChainBreakCause::Anchor);
    let (state, _verified) = verification_scenario(Ok(ChainVerification::invalid(2, broken)));

    let response = run(&schema(Some(state)), Caller::Valid, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "securityAuditChainVerification": {
            "status": "invalid",
            "recordsChecked": 2,
            "invalidRecordId": "00000000-0000-0000-0000-000000000002",
            "invalidSeq": 2,
            "cause": "anchor",
        } })
    );
}

#[tokio::test]
async fn the_anchors_reach_the_query() {
    let (state, verified) = verification_scenario(Ok(ChainVerification::valid(3)));

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        json!({ "anchors": [{ "seq": 2, "hash": HASH }, { "seq": 3, "hash": HASH }] }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let asked = verified.lock().unwrap_or_else(PoisonError::into_inner);
    let seqs: Vec<i64> = asked[0]
        .anchors
        .iter()
        .map(iam_domain::AuditChainHead::seq)
        .collect();
    assert_eq!(seqs, [2, 3]);
    assert_eq!(asked[0].anchors[1].hash().to_string(), HASH);
}

#[tokio::test]
async fn an_invalid_anchor_is_a_validation_error_without_a_query() {
    let (state, verified) = verification_scenario(Ok(ChainVerification::valid(0)));

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        json!({ "anchors": [{ "seq": 0, "hash": HASH }] }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(Value::String("VALIDATION_FAILED".to_owned()))
    );
    assert!(
        verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    );
}

#[tokio::test]
async fn a_request_without_a_valid_caller_is_unauthenticated_without_a_query() {
    for caller in [Caller::Absent, Caller::Refused] {
        let (state, verified) = verification_scenario(Ok(ChainVerification::valid(0)));

        let response = run(&schema(Some(state)), caller, json!({})).await;

        assert_eq!(
            error_code(&response),
            Some(Value::String("UNAUTHENTICATED".to_owned()))
        );
        assert!(
            verified
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }
}

#[tokio::test]
async fn a_request_without_the_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(Value::String("INTERNAL_SERVER_ERROR".to_owned()))
    );
}

#[tokio::test]
async fn a_verification_that_cannot_be_audited_is_an_internal_error() {
    let (state, _verified) = verification_scenario(Err(|| IamError::Storage("down".into())));

    let response = run(&schema(Some(state)), Caller::Valid, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(Value::String("INTERNAL_SERVER_ERROR".to_owned()))
    );
}

#[test]
fn an_anchor_input_prints_its_type_and_its_fields() {
    let anchor = SecurityAuditAnchorInput {
        seq: 2,
        hash: HASH.to_owned(),
    };

    let printed = format!("{anchor:?}");

    assert!(printed.starts_with("SecurityAuditAnchorInput"));
    assert!(printed.contains(HASH));
    assert_eq!(anchor, anchor.clone());
}

#[test]
fn an_anchor_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let anchor = Value::Object(
        [
            (Name::new("seq"), Value::from(2)),
            (Name::new("hash"), Value::String(HASH.to_owned())),
        ]
        .into_iter()
        .collect(),
    );

    let parsed = SecurityAuditAnchorInput::parse(Some(anchor)).unwrap();

    assert_eq!(parsed.seq, 2);
    assert_eq!(parsed.hash, HASH);
    assert!(SecurityAuditAnchorInput::parse(Some(Value::Boolean(true))).is_err());
    for (seq, hash) in [
        (Value::Boolean(true), Value::String(HASH.to_owned())),
        (Value::from(2), Value::Boolean(true)),
    ] {
        let wrong = Value::Object(
            [(Name::new("seq"), seq), (Name::new("hash"), hash)]
                .into_iter()
                .collect(),
        );
        assert!(SecurityAuditAnchorInput::parse(Some(wrong)).is_err());
    }
}
