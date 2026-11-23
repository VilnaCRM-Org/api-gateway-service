use iam_domain::SpecId;
use serde_json::json;

use super::{RetireSpecRequest, SpecRetirementResponse};

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

#[test]
fn the_confirmation_defaults_to_false() {
    let request: RetireSpecRequest = serde_json::from_str("{}").unwrap();

    assert!(!request.confirm_orphans);
}

#[test]
fn the_confirmation_is_read_in_camel_case() {
    let request: RetireSpecRequest = serde_json::from_str(r#"{"confirmOrphans": true}"#).unwrap();

    assert!(request.confirm_orphans);
}

#[test]
fn an_unknown_field_is_refused() {
    let refused = serde_json::from_str::<RetireSpecRequest>(r#"{"confirm_orphans": true}"#);

    assert!(refused.is_err());
}

#[test]
fn the_canonical_form_names_the_operation_the_version_and_the_confirmation() {
    let id = SpecId::parse(SPEC).unwrap();
    let confirmed = RetireSpecRequest {
        confirm_orphans: true,
    };

    assert_eq!(
        confirmed.canonical_form("graphql_spec", id),
        format!("graphql_spec.retire:(\"{SPEC}\", true)")
    );
    assert_ne!(
        confirmed.canonical_form("graphql_spec", id),
        RetireSpecRequest::default().canonical_form("graphql_spec", id)
    );
    assert_ne!(
        confirmed.canonical_form("graphql_spec", id),
        confirmed.canonical_form("openapi_spec", id)
    );
}

#[test]
fn the_response_is_camel_case() {
    let response = SpecRetirementResponse {
        id: SPEC.to_owned(),
        service: "billing".to_owned(),
        status: "retired".to_owned(),
        policy_version: 4,
    };

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({"id": SPEC, "service": "billing", "status": "retired", "policyVersion": 4})
    );
}
