use iam_domain::{AccessTarget, DecisionReason, HttpMethod, PolicyVersion, RequestId};
use rstest::rstest;
use serde_json::{Value, json};
use validator::Validate as _;

use super::{AccessValidationResponse, ParsedValidation, ValidateAccessRequest};
use crate::access_validation_fixtures::{
    DECISION, PROJECT, SUBJECT, allowed, allowed_in_project, denied, token_refused,
};
use crate::error::IamError;

fn request(overrides: &Value) -> ValidateAccessRequest {
    let mut body = json!({
        "credential": "subject-token",
        "service": "billing",
        "rest": {"method": "GET", "path": "/api/invoices/42"},
        "requestId": "req-1"
    });
    if let (Some(fields), Some(extra)) = (body.as_object_mut(), overrides.as_object()) {
        for (name, value) in extra {
            if value.is_null() {
                fields.remove(name);
            } else {
                fields.insert(name.clone(), value.clone());
            }
        }
    }
    serde_json::from_value(body).unwrap()
}

fn violations(request: ValidateAccessRequest) -> Vec<(String, String)> {
    let IamError::Invalid(violations) = request.parse().unwrap_err() else {
        panic!("expected violations");
    };
    violations
        .into_iter()
        .map(|violation| (violation.property_path, violation.code))
        .collect()
}

fn parsed(request: ValidateAccessRequest) -> ParsedValidation {
    request.parse().unwrap()
}

fn pair(path: &str, code: &str) -> (String, String) {
    (path.to_owned(), code.to_owned())
}

#[test]
fn a_rest_check_parses_into_a_query_with_the_request_id() {
    let parsed = parsed(request(&json!({})));

    assert_eq!(parsed.request_id, RequestId::new("req-1").unwrap());
    assert_eq!(parsed.query.credential.expose(), "subject-token");
    assert_eq!(parsed.query.check.service().as_str(), "billing");
    let AccessTarget::Rest(target) = parsed.query.check.target() else {
        panic!("expected a REST target");
    };
    assert_eq!(target.method(), HttpMethod::Get);
    assert_eq!(target.path(), "/api/invoices/42");
    assert_eq!(parsed.query.check.project(), None);
    assert_eq!(parsed.query.check.min_policy_version(), None);
}

#[test]
fn a_permissions_check_keeps_the_keys_in_request_order() {
    let keys = ["rest:billing:GET /api/invoices", "iam:validate:*"];
    let parsed = parsed(request(&json!({"rest": null, "permissions": keys})));

    let AccessTarget::Permissions(target) = parsed.query.check.target() else {
        panic!("expected a permissions target");
    };
    assert_eq!(target.keys(), keys);
}

#[test]
fn the_project_and_the_minimum_version_are_parsed_when_given() {
    let parsed = parsed(request(
        &json!({"projectId": PROJECT, "minPolicyVersion": 3}),
    ));

    assert_eq!(
        parsed
            .query
            .check
            .project()
            .map(|project| project.to_string()),
        Some(PROJECT.to_owned())
    );
    assert_eq!(
        parsed.query.check.min_policy_version(),
        Some(PolicyVersion::new(3).unwrap())
    );
}

#[test]
fn an_empty_credential_is_still_a_request() {
    let parsed = parsed(request(&json!({"credential": ""})));

    assert!(parsed.query.credential.is_blank());
}

#[test]
fn a_request_with_no_target_form_is_a_violation_of_the_target() {
    let found = violations(request(&json!({"rest": null})));

    assert_eq!(found, [pair("target", "choice")]);
}

#[test]
fn a_request_with_two_target_forms_is_a_violation_of_the_target() {
    let found = violations(request(&json!({"permissions": ["iam:validate:*"]})));

    assert_eq!(found, [pair("target", "choice")]);
}

#[test]
fn a_graphql_check_parses_into_a_query_with_the_document_and_the_operation_name() {
    let parsed = parsed(request(&json!({
        "rest": null,
        "graphql": {"document": "query Get { invoice { id } }", "operationName": "Get"}
    })));

    let AccessTarget::GraphQl(target) = parsed.query.check.target() else {
        panic!("expected a GraphQL target");
    };
    assert_eq!(target.document(), "query Get { invoice { id } }");
    assert_eq!(target.operation_name(), Some("Get"));
}

#[test]
fn a_graphql_check_without_an_operation_name_names_none() {
    let parsed = parsed(request(&json!({
        "rest": null,
        "graphql": {"document": "{ invoice { id } }"}
    })));

    let AccessTarget::GraphQl(target) = parsed.query.check.target() else {
        panic!("expected a GraphQL target");
    };
    assert_eq!(target.operation_name(), None);
}

#[test]
fn a_graphql_document_over_the_limits_is_not_refused_by_validation() {
    let document = "x".repeat(200 * 1024);
    let request = request(&json!({"rest": null, "graphql": {"document": document}}));

    assert!(request.validate().is_ok());
    assert!(request.parse().is_ok());
}

#[test]
fn an_operation_name_beyond_256_characters_is_refused_by_validation() {
    let request = request(&json!({
        "rest": null,
        "graphql": {"document": "{ a }", "operationName": "n".repeat(257)}
    }));

    assert!(request.validate().is_err());
}

#[rstest]
#[case::with_rest(json!({"graphql": {"document": "{ a }"}}))]
#[case::with_permissions(json!({
    "rest": null,
    "graphql": {"document": "{ a }"},
    "permissions": ["iam:validate:*"]
}))]
#[case::with_both(json!({
    "graphql": {"document": "{ a }"},
    "permissions": ["iam:validate:*"]
}))]
fn a_graphql_target_beside_another_form_is_a_violation_of_the_target(#[case] overrides: Value) {
    let found = violations(request(&overrides));

    assert_eq!(found, [pair("target", "choice")]);
}

#[test]
fn the_graphql_target_refuses_an_unknown_member() {
    let body = json!({
        "credential": "t", "service": "billing", "requestId": "r",
        "graphql": {"document": "{ a }", "extra": 1}
    });

    assert!(serde_json::from_value::<ValidateAccessRequest>(body).is_err());
}

#[test]
fn an_unknown_method_is_a_violation_of_the_method() {
    let found = violations(request(&json!({"rest": {"method": "get", "path": "/"}})));

    assert_eq!(found, [pair("rest.method", "choice")]);
}

#[test]
fn every_violation_is_reported_in_the_order_of_the_fields() {
    let found = violations(request(&json!({
        "service": "Not A Service",
        "rest": null,
        "permissions": ["iam:validate:*"],
        "projectId": "not-a-uuid",
        "minPolicyVersion": -1,
        "requestId": "has a space"
    })));

    assert_eq!(
        found,
        [
            pair("service", "pattern"),
            pair("projectId", "uuid"),
            pair("minPolicyVersion", "range"),
            pair("requestId", "format"),
        ]
    );
}

#[test]
fn more_than_one_hundred_keys_are_refused_by_validation() {
    let many = |count: usize| -> Vec<String> {
        (0..count)
            .map(|index| format!("iam:validate:{index}"))
            .collect()
    };
    let too_many = request(&json!({"rest": null, "permissions": many(101)}));
    let limit = request(&json!({"rest": null, "permissions": many(100)}));

    assert!(too_many.validate().is_err());
    assert!(limit.validate().is_ok());
}

#[test]
fn an_empty_list_of_keys_is_refused_by_validation_and_by_parsing() {
    let empty = request(&json!({"rest": null, "permissions": []}));

    assert!(empty.validate().is_err());
    assert_eq!(violations(empty), [pair("permissions", "count")]);
}

#[rstest]
#[case::empty_service(json!({"service": ""}))]
#[case::long_service(json!({"service": "a".repeat(64)}))]
#[case::empty_request_id(json!({"requestId": ""}))]
#[case::long_request_id(json!({"requestId": "r".repeat(129)}))]
#[case::long_credential(json!({"credential": "c".repeat(8193)}))]
#[case::long_project(json!({"projectId": "p".repeat(65)}))]
#[case::empty_method(json!({"rest": {"method": "", "path": "/"}}))]
fn a_value_beyond_its_length_is_refused_by_validation(#[case] overrides: Value) {
    assert!(request(&overrides).validate().is_err());
}

#[test]
fn the_body_refuses_an_unknown_member() {
    let body = json!({
        "credential": "t", "service": "billing", "requestId": "r", "extra": 1
    });

    assert!(serde_json::from_value::<ValidateAccessRequest>(body).is_err());
}

#[test]
fn the_request_does_not_print_the_credential() {
    let printed = format!("{:?}", request(&json!({"credential": "raw-secret-token"})));

    assert!(!printed.contains("raw-secret-token"), "{printed}");
}

#[test]
fn an_allow_for_every_project_is_the_string_all() {
    let body = AccessValidationResponse::new(&allowed(), &RequestId::new("req-1").unwrap());

    assert_eq!(
        serde_json::to_value(&body).unwrap(),
        json!({
            "decision": "allow",
            "reason": "allowed",
            "denied": [],
            "scopes": "all",
            "subject": {"id": SUBJECT, "kind": "user"},
            "decisionId": DECISION,
            "policyVersion": 7,
            "requestId": "req-1"
        })
    );
}

#[test]
fn an_allow_in_one_project_lists_the_project_ids() {
    let body =
        AccessValidationResponse::new(&allowed_in_project(), &RequestId::new("req-1").unwrap());

    assert_eq!(
        serde_json::to_value(&body).unwrap()["scopes"],
        json!([PROJECT])
    );
}

#[test]
fn a_deny_lists_the_denied_keys_and_no_scopes() {
    let outcome = denied(
        DecisionReason::PermissionMissing,
        &["rest:billing:GET /api/invoices/{}"],
    );

    let body = serde_json::to_value(AccessValidationResponse::new(
        &outcome,
        &RequestId::new("req-2").unwrap(),
    ))
    .unwrap();

    assert_eq!(body["decision"], "deny");
    assert_eq!(body["reason"], "permission_missing");
    assert_eq!(body["denied"], json!(["rest:billing:GET /api/invoices/{}"]));
    assert_eq!(body["scopes"], json!([]));
    assert_eq!(body["requestId"], "req-2");
}

#[test]
fn a_refused_token_leaves_out_the_subject_and_the_policy_version() {
    let body = serde_json::to_value(AccessValidationResponse::new(
        &token_refused(),
        &RequestId::new("req-3").unwrap(),
    ))
    .unwrap();

    assert_eq!(body["reason"], "token_expired");
    assert!(body.get("subject").is_none());
    assert!(body.get("policyVersion").is_none());
}
