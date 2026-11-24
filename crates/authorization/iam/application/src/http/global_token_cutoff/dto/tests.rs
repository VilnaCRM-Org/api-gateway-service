use validator::Validate as _;

use super::SetGlobalTokenCutoffRequest;

#[test]
fn an_empty_object_is_valid() {
    assert!(SetGlobalTokenCutoffRequest::default().validate().is_ok());
}

#[test]
fn an_object_with_a_member_is_refused_with_a_violation_of_the_body() {
    let request: SetGlobalTokenCutoffRequest =
        serde_json::from_str(r#"{"at": "2026-01-01T00:00:00Z"}"#).unwrap();

    let errors = request.validate().unwrap_err();

    assert!(errors.errors().contains_key("body"));
}

#[test]
fn the_canonical_form_names_the_operation() {
    assert_eq!(
        SetGlobalTokenCutoffRequest::canonical_form(),
        "global_token.cut_off"
    );
}
