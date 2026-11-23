use iam_domain::SpecId;
use serde_json::json;
use validator::Validate as _;

use super::{CreateGraphQlPermissionsRequest, GraphQlPermissionsActivationResponse, KeyRenameDto};
use crate::error::IamError;

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn rename(from: &str, to: &str) -> KeyRenameDto {
    KeyRenameDto {
        from: from.to_owned(),
        to: to.to_owned(),
    }
}

fn request(renames: Vec<KeyRenameDto>) -> CreateGraphQlPermissionsRequest {
    CreateGraphQlPermissionsRequest {
        renames,
        ..CreateGraphQlPermissionsRequest::default()
    }
}

#[test]
fn an_empty_body_is_a_request_without_confirmations_or_renames() {
    let parsed: CreateGraphQlPermissionsRequest = serde_json::from_value(json!({})).unwrap();

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
    let parsed: CreateGraphQlPermissionsRequest = serde_json::from_value(json!({
        "confirmOrphans": true,
        "confirmFlagDowngrade": true,
        "renames": [{"from": "gql:billing:Query.bills", "to": "gql:billing:Query.invoices"}]
    }))
    .unwrap();

    assert!(parsed.confirm_orphans);
    assert!(parsed.confirm_flag_downgrade);
    let pairs = parsed.parse().unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.to_string(), "gql:billing:Query.bills");
    assert_eq!(pairs[0].1.to_string(), "gql:billing:Query.invoices");
}

#[test]
fn an_unknown_field_is_refused() {
    let parsed =
        serde_json::from_value::<CreateGraphQlPermissionsRequest>(json!({"confirm": true}));

    assert!(parsed.is_err());
}

#[test]
fn a_rename_with_an_empty_key_fails_validation() {
    let invalid = request(vec![rename("", "gql:billing:Query.invoices")]);

    assert!(invalid.validate().is_err());
}

#[test]
fn more_than_a_thousand_renames_fail_validation() {
    let many = request(
        (0..=1000)
            .map(|_| rename("gql:billing:Query.a", "gql:billing:Query.b"))
            .collect(),
    );

    assert!(many.validate().is_err());
}

#[test]
fn a_rename_that_is_not_a_key_is_a_violation_of_its_position() {
    let invalid = request(vec![
        rename("gql:billing:Query.bills", "gql:billing:Query.invoices"),
        rename("nonsense", "also nonsense"),
    ]);

    let IamError::Invalid(violations) = invalid.parse().unwrap_err() else {
        panic!("violations expected");
    };

    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["renames[1].from", "renames[1].to"]);
    assert_eq!(violations[0].code, "kind");
}

#[test]
fn only_the_bad_side_of_a_rename_is_a_violation() {
    let invalid = request(vec![rename("gql:billing:Query.bills", "nonsense")]);

    let IamError::Invalid(violations) = invalid.parse().unwrap_err() else {
        panic!("violations expected");
    };

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "renames[0].to");
}

#[test]
fn the_canonical_form_differs_for_another_version_confirmation_or_rename() {
    let id = SpecId::parse(SPEC).unwrap();
    let other = SpecId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ae").unwrap();
    let base = request(Vec::new());
    let forms = [
        base.canonical_form(id),
        base.canonical_form(other),
        CreateGraphQlPermissionsRequest {
            confirm_orphans: true,
            ..base.clone()
        }
        .canonical_form(id),
        CreateGraphQlPermissionsRequest {
            confirm_flag_downgrade: true,
            ..base.clone()
        }
        .canonical_form(id),
        request(vec![rename("a", "b")]).canonical_form(id),
    ];

    let distinct: std::collections::BTreeSet<&String> = forms.iter().collect();
    assert_eq!(distinct.len(), forms.len());
    assert_eq!(base.canonical_form(id), base.canonical_form(id));
}

#[test]
fn the_response_is_written_in_camel_case() {
    let response = GraphQlPermissionsActivationResponse {
        id: SPEC.to_owned(),
        service: "billing".to_owned(),
        status: "active".to_owned(),
        created_keys: vec!["gql:billing:Query.invoices".to_owned()],
        policy_version: 4,
    };

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "id": SPEC,
            "service": "billing",
            "status": "active",
            "createdKeys": ["gql:billing:Query.invoices"],
            "policyVersion": 4
        })
    );
}
