use rstest::rstest;

use super::AuditReason;
use crate::error::InvalidIamValue;

#[rstest]
#[case("forbidden")]
#[case("escalation.denied")]
#[case("caller_not_allowed")]
#[case("r2")]
fn accepts_lower_case_codes(#[case] text: &str) {
    assert_eq!(AuditReason::new(text).unwrap().as_str(), text);
}

#[test]
fn accepts_a_reason_of_exactly_the_maximum_length() {
    let text = "a".repeat(AuditReason::MAX_LENGTH);

    assert!(AuditReason::new(&text).is_ok());
}

#[rstest]
#[case("")]
#[case("Forbidden")]
#[case("1forbidden")]
#[case(".forbidden")]
#[case("not-allowed")]
#[case("not allowed")]
fn rejects_anything_else(#[case] text: &str) {
    assert_eq!(
        AuditReason::new(text),
        Err(InvalidIamValue::AuditReasonFormat)
    );
}

#[test]
fn rejects_a_reason_over_the_maximum_length() {
    let text = "a".repeat(AuditReason::MAX_LENGTH + 1);

    assert_eq!(
        AuditReason::new(&text),
        Err(InvalidIamValue::AuditReasonFormat)
    );
}
