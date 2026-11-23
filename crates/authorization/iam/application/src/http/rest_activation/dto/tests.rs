use iam_domain::SpecId;
use serde_json::json;
use validator::Validate as _;

use super::{CreateRestPermissionsRequest, RestPermissionsActivationResponse};
use crate::error::IamError;
use crate::http::graphql_activation::dto::KeyRenameDto;

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn rename(from: &str, to: &str) -> KeyRenameDto {
    KeyRenameDto {
        from: from.to_owned(),
        to: to.to_owned(),
    }
}

fn request(renames: Vec<KeyRenameDto>) -> CreateRestPermissionsRequest {
    CreateRestPermissionsRequest {
        renames,
        ..CreateRestPermissionsRequest::default()
    }
}

#[test]
fn an_empty_body_is_a_request_without_confirmations_or_renames() {
    let parsed: CreateRestPermissionsRequest = serde_json::from_value(json!({})).unwrap();

    assert!(!parsed.confirm_orphans);
    assert!(!parsed.confirm_flag_downgrade);
    assert_eq!(parsed.renames, Vec::<KeyRenameDto>::new());
    assert!(parsed.validate().is_ok());
    assert_eq!(
        parsed.parse().unwrap(),
        Vec::<(iam_domain::PermissionKey, iam_domain::PermissionKey)>::new()
    );
}

#[test]
fn the_body_reads_the_confirmations_and_the_renames() {
    let parsed: CreateRestPermissionsRequest = serde_json::from_value(json!({
        "confirmOrphans": true,
        "confirmFlagDowngrade": true,
        "renames": [{"from": "rest:billing:GET /bills", "to": "rest:billing:GET /invoices"}]
    }))
    .unwrap();

    assert!(parsed.confirm_orphans);
    assert!(parsed.confirm_flag_downgrade);
    let pairs = parsed.parse().unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.to_string(), "rest:billing:GET /bills");
    assert_eq!(pairs[0].1.to_string(), "rest:billing:GET /invoices");
}

#[test]
fn an_unknown_field_is_refused() {
    let parsed = serde_json::from_value::<CreateRestPermissionsRequest>(json!({"confirm": true}));

    assert!(parsed.is_err());
}

#[test]
fn a_rename_with_an_empty_key_fails_validation() {
    let invalid = request(vec![rename("", "rest:billing:GET /invoices")]);

    assert!(invalid.validate().is_err());
}

#[test]
fn more_than_a_thousand_renames_fail_validation() {
    let many = request(vec![rename("rest:a:GET /a", "rest:a:GET /b"); 1001]);

    assert!(many.validate().is_err());
}

#[test]
fn a_rename_that_is_not_a_key_is_a_violation_of_its_path() {
    let invalid = request(vec![rename("rest:billing:GET /bills", "not a key")]);

    let IamError::Invalid(violations) = invalid.parse().unwrap_err() else {
        panic!("violations expected");
    };

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "renames[0].to");
}

#[test]
fn the_digest_text_names_the_operation_the_version_and_the_body() {
    let id = SpecId::parse(SPEC).unwrap();
    let plain = request(Vec::new()).canonical_form(id);
    let renaming = request(vec![rename("rest:a:GET /a", "rest:a:GET /b")]).canonical_form(id);
    let confirming = CreateRestPermissionsRequest {
        confirm_orphans: true,
        ..CreateRestPermissionsRequest::default()
    }
    .canonical_form(id);

    assert!(plain.starts_with("openapi_spec.activate:"));
    assert!(plain.contains(SPEC));
    assert_ne!(plain, renaming);
    assert_ne!(plain, confirming);
}

#[test]
fn the_response_is_written_in_camel_case() {
    let response = RestPermissionsActivationResponse {
        id: SPEC.to_owned(),
        service: "billing".to_owned(),
        status: "active".to_owned(),
        created_keys: vec!["rest:billing:GET /invoices".to_owned()],
        policy_version: 4,
    };

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "id": SPEC,
            "service": "billing",
            "status": "active",
            "createdKeys": ["rest:billing:GET /invoices"],
            "policyVersion": 4
        })
    );
}
