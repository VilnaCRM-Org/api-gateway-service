use rstest::rstest;

use super::AuditSummary;
use crate::error::InvalidIamValue;

#[rstest]
#[case("role=admins")]
#[case("permissions=rest:core:GET:/api/customers,gql:core:Query.customers")]
#[case("name=Caf\u{e9} owners")]
#[case("eyJhbGciOiJSUzI1NiJ9.only-two")]
#[case("eyJhbGciOiJSUzI1NiJ9..empty-middle")]
#[case("abc.def.ghi")]
fn accepts_one_line_of_printable_identifiers(#[case] text: &str) {
    let summary = AuditSummary::new(text).unwrap();

    assert_eq!(summary.as_str(), text);
}

#[test]
fn accepts_a_summary_of_exactly_the_maximum_length() {
    let text = "a".repeat(AuditSummary::MAX_LENGTH);

    assert!(AuditSummary::new(&text).is_ok());
}

#[rstest]
#[case("")]
#[case("openapi: 3.1.0\ninfo: {}")]
#[case("tab\there")]
#[case("token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl")]
#[case("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln-_bmF0")]
#[case("[eyJh.b.c]")]
fn rejects_empty_text_control_characters_and_tokens(#[case] text: &str) {
    assert_eq!(
        AuditSummary::new(text),
        Err(InvalidIamValue::AuditSummaryFormat)
    );
}

#[test]
fn rejects_a_summary_over_the_maximum_length() {
    let text = "a".repeat(AuditSummary::MAX_LENGTH + 1);

    assert_eq!(
        AuditSummary::new(&text),
        Err(InvalidIamValue::AuditSummaryFormat)
    );
}
