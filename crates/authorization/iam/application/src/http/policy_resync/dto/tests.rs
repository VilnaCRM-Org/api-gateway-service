use rstest::rstest;
use validator::Validate as _;

use super::{MAX_REASON_CHARS, ResyncPolicyRequest};

fn request(reason: &str) -> ResyncPolicyRequest {
    ResyncPolicyRequest {
        reason: reason.to_owned(),
    }
}

#[test]
fn the_reason_is_read_from_the_body() {
    let parsed: ResyncPolicyRequest =
        serde_json::from_str(r#"{"reason": "broker failure"}"#).unwrap();

    assert_eq!(parsed, request("broker failure"));
    assert!(parsed.validate().is_ok());
}

#[test]
fn a_missing_reason_is_read_as_empty_so_that_it_fails_validation() {
    let parsed: ResyncPolicyRequest = serde_json::from_str("{}").unwrap();

    assert_eq!(parsed.reason, "");
    assert!(parsed.validate().is_err());
}

#[test]
fn an_unknown_field_is_refused() {
    let refused = serde_json::from_str::<ResyncPolicyRequest>(r#"{"reason": "x", "force": true}"#);

    assert!(refused.is_err());
}

#[rstest]
#[case::empty("")]
#[case::blank("   ")]
#[case::new_line("first line\nsecond line")]
#[case::tab("a\tb")]
fn an_unusable_reason_fails_validation(#[case] reason: &str) {
    assert!(request(reason).validate().is_err());
}

#[test]
fn a_reason_of_501_characters_fails_validation() {
    assert!(
        request(&"a".repeat(MAX_REASON_CHARS + 1))
            .validate()
            .is_err()
    );
}

#[rstest]
#[case::one_character("x")]
#[case::sentence("The state topic lost records after a broker failure.")]
fn a_one_line_reason_is_valid(#[case] reason: &str) {
    assert!(request(reason).validate().is_ok());
}

#[test]
fn a_reason_of_500_characters_is_valid() {
    assert!(request(&"a".repeat(MAX_REASON_CHARS)).validate().is_ok());
}

#[test]
fn the_canonical_form_names_the_operation_and_the_reason() {
    assert_eq!(
        request("broker failure").canonical_form(),
        "policy.resync:\"broker failure\""
    );
    assert_ne!(
        request("broker failure").canonical_form(),
        request("another reason").canonical_form()
    );
}
