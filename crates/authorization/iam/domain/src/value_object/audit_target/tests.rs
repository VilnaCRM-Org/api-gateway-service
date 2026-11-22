use rstest::rstest;

use super::AuditTarget;
use crate::error::InvalidIamValue;

#[rstest]
#[case("role", "0190f2a8-7b3c-7d4e-8f00-123456789abc")]
#[case("user_role", "x")]
#[case("spec2", "service:core")]
fn accepts_a_lower_case_type_and_a_visible_ascii_id(#[case] target_type: &str, #[case] id: &str) {
    let target = AuditTarget::new(target_type, id).unwrap();

    assert_eq!(target.target_type(), target_type);
    assert_eq!(target.target_id(), id);
}

#[test]
fn accepts_a_type_and_an_id_of_exactly_the_maximum_length() {
    let target_type = "a".repeat(AuditTarget::MAX_TYPE_LENGTH);
    let id = "b".repeat(AuditTarget::MAX_ID_LENGTH);

    assert!(AuditTarget::new(&target_type, &id).is_ok());
}

#[rstest]
#[case("")]
#[case("Role")]
#[case("1role")]
#[case("_role")]
#[case("user-role")]
#[case("role.kind")]
#[case("role ")]
fn rejects_any_other_type(#[case] target_type: &str) {
    assert_eq!(
        AuditTarget::new(target_type, "id"),
        Err(InvalidIamValue::AuditTargetType)
    );
}

#[test]
fn rejects_a_type_over_the_maximum_length() {
    let target_type = "a".repeat(AuditTarget::MAX_TYPE_LENGTH + 1);

    assert_eq!(
        AuditTarget::new(&target_type, "id"),
        Err(InvalidIamValue::AuditTargetType)
    );
}

#[rstest]
#[case("")]
#[case("with space")]
#[case("tab\tid")]
#[case("caf\u{e9}")]
fn rejects_an_id_that_is_empty_or_not_visible_ascii(#[case] id: &str) {
    assert_eq!(
        AuditTarget::new("role", id),
        Err(InvalidIamValue::AuditTargetId)
    );
}

#[test]
fn rejects_an_id_over_the_maximum_length() {
    let id = "b".repeat(AuditTarget::MAX_ID_LENGTH + 1);

    assert_eq!(
        AuditTarget::new("role", &id),
        Err(InvalidIamValue::AuditTargetId)
    );
}
