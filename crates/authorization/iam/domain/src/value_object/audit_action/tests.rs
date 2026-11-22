use rstest::rstest;

use super::AuditAction;
use crate::error::InvalidIamValue;

#[rstest]
#[case("role.create")]
#[case("user_role.revoke")]
#[case("spec.activate.v2")]
#[case("a.b")]
fn accepts_dotted_lower_case_words(#[case] text: &str) {
    let action = AuditAction::new(text).unwrap();

    assert_eq!(action.as_str(), text);
    assert_eq!(action.to_string(), text);
}

#[test]
fn accepts_an_action_of_exactly_the_maximum_length() {
    let text = format!("a.{}", "b".repeat(AuditAction::MAX_LENGTH - 2));

    assert!(AuditAction::new(&text).is_ok());
}

#[rstest]
#[case("")]
#[case("role")]
#[case("Role.create")]
#[case("role.")]
#[case(".create")]
#[case("role..create")]
#[case("role.1create")]
#[case("1role.create")]
#[case("role.cre-ate")]
#[case("role.create ")]
fn rejects_anything_else(#[case] text: &str) {
    assert_eq!(
        AuditAction::new(text),
        Err(InvalidIamValue::AuditActionFormat)
    );
}

#[test]
fn rejects_an_action_over_the_maximum_length() {
    let text = format!("a.{}", "b".repeat(AuditAction::MAX_LENGTH - 1));

    assert_eq!(
        AuditAction::new(&text),
        Err(InvalidIamValue::AuditActionFormat)
    );
}
