use iam_domain::{AccessTarget, DecisionReason};
use serde_json::{Value, json};
use validator::Validate as _;

use super::{AccessValidationBatchResponse, ValidateAccessBatchRequest};
use crate::access_validation_fixtures::{DECISION, allowed, denied};
use crate::query::validate_access_batch::BatchCheck;

fn item(overrides: &Value) -> Value {
    let mut body = json!({
        "credential": "subject-token",
        "service": "billing",
        "rest": {"method": "GET", "path": "/api/invoices/42"},
        "requestId": "req-1"
    });
    if let (Some(fields), Some(extra)) = (body.as_object_mut(), overrides.as_object()) {
        for (name, value) in extra {
            fields.insert(name.clone(), value.clone());
        }
    }
    body
}

fn batch(items: &[Value]) -> ValidateAccessBatchRequest {
    serde_json::from_value(json!({ "checks": items })).unwrap()
}

#[test]
fn a_batch_of_one_hundred_checks_validates() {
    let request = batch(&vec![item(&json!({})); 100]);

    assert!(request.validate().is_ok());
}

#[test]
fn a_batch_of_one_hundred_and_one_checks_is_refused_by_validation() {
    let request = batch(&vec![item(&json!({})); 101]);

    assert!(request.validate().is_err());
}

#[test]
fn an_empty_batch_is_refused_by_validation() {
    let request = batch(&[]);

    assert!(request.validate().is_err());
}

#[test]
fn a_batch_with_a_malformed_item_still_validates_as_a_whole() {
    let request = batch(&[item(&json!({})), item(&json!({"service": ""}))]);

    assert!(request.validate().is_ok());
}

#[test]
fn the_body_refuses_an_unknown_member() {
    let body = json!({"checks": [item(&json!({}))], "extra": true});

    assert!(serde_json::from_value::<ValidateAccessBatchRequest>(body).is_err());
}

#[test]
fn the_request_does_not_print_a_credential() {
    let printed = format!("{:?}", batch(&[item(&json!({}))]));

    assert!(!printed.contains("subject-token"), "{printed}");
}

#[test]
fn every_item_parses_into_a_check_in_request_order() {
    let parsed = batch(&[
        item(&json!({"requestId": "first"})),
        item(&json!({
            "requestId": "second", "rest": null,
            "permissions": ["rest:billing:GET /api/invoices"]
        })),
    ])
    .parse();

    assert_eq!(parsed.request_ids, ["first", "second"]);
    let [BatchCheck::Valid(first), BatchCheck::Valid(second)] = parsed.query.checks.as_slice()
    else {
        panic!("expected two valid checks, got {:?}", parsed.query);
    };
    assert!(matches!(first.check.target(), AccessTarget::Rest(_)));
    assert!(matches!(
        second.check.target(),
        AccessTarget::Permissions(_)
    ));
}

#[test]
fn an_item_that_breaks_a_wire_rule_is_malformed_and_keeps_its_request_id() {
    let too_long = "x".repeat(8193);

    let parsed = batch(&[
        item(&json!({"credential": too_long, "requestId": "long"})),
        item(&json!({"requestId": "fine"})),
    ])
    .parse();

    assert_eq!(parsed.request_ids, ["long", "fine"]);
    assert!(matches!(
        parsed.query.checks.as_slice(),
        [BatchCheck::Malformed, BatchCheck::Valid(_)]
    ));
}

#[test]
fn an_item_that_breaks_a_parsing_rule_is_malformed() {
    let parsed = batch(&[
        item(&json!({"rest": {"method": "FETCH", "path": "/x"}})),
        item(&json!({"rest": null})),
        item(&json!({"service": "Not A Service"})),
    ])
    .parse();

    assert!(matches!(
        parsed.query.checks.as_slice(),
        [
            BatchCheck::Malformed,
            BatchCheck::Malformed,
            BatchCheck::Malformed
        ]
    ));
}

#[test]
fn the_results_follow_the_outcomes_and_echo_each_request_id() {
    let outcomes = [
        allowed(),
        denied(DecisionReason::PermissionMissing, &["key"]),
    ];

    let response =
        AccessValidationBatchResponse::new(&outcomes, vec!["a".to_owned(), "b".to_owned()]);

    let [first, second] = response.results.as_slice() else {
        panic!("expected two results");
    };
    assert_eq!(first.decision, "allow");
    assert_eq!(first.request_id, "a");
    assert_eq!(first.decision_id, DECISION);
    assert_eq!(second.decision, "deny");
    assert_eq!(second.reason, "permission_missing");
    assert_eq!(second.denied, ["key"]);
    assert_eq!(second.request_id, "b");
}
