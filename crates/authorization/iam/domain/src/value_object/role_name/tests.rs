use rstest::rstest;

use super::RoleName;
use crate::error::InvalidRole;

#[rstest]
#[case::one_character("a")]
#[case::spaces_inside("Billing administrators")]
#[case::non_ascii("Comptabilité")]
fn accepts_a_valid_name(#[case] value: &str) {
    let name = RoleName::new(value.to_owned()).unwrap();

    assert_eq!(name.as_str(), value);
    assert_eq!(name.to_string(), value);
}

#[test]
fn accepts_exactly_the_maximum_number_of_characters() {
    let value = "é".repeat(RoleName::MAX_CHARS);

    assert_eq!(RoleName::new(value.clone()).unwrap().as_str(), value);
}

#[rstest]
#[case::empty(String::new())]
#[case::one_character_too_many("é".repeat(RoleName::MAX_CHARS + 1))]
#[case::too_long_with_a_control_character(format!("{}\n", "a".repeat(RoleName::MAX_CHARS)))]
fn rejects_a_name_of_the_wrong_length(#[case] value: String) {
    assert_eq!(RoleName::new(value), Err(InvalidRole::NameLength));
}

#[rstest]
#[case::nul("Billing\0")]
#[case::new_line("Bill\ning")]
#[case::tab("\tBilling")]
#[case::delete("Billing\u{7f}")]
#[case::c1_control("Billing\u{85}")]
fn rejects_a_name_with_a_control_character(#[case] value: &str) {
    assert_eq!(
        RoleName::new(value.to_owned()),
        Err(InvalidRole::NameControlCharacter)
    );
}

#[test]
fn compares_names_without_regard_to_case() {
    let upper = RoleName::new("BILLING Admins".to_owned()).unwrap();
    let lower = RoleName::new("billing admins".to_owned()).unwrap();
    let other = RoleName::new("billing".to_owned()).unwrap();

    assert_eq!(upper.comparison_form(), "billing admins");
    assert!(upper.same_as(&lower));
    assert!(!upper.same_as(&other));
    assert_ne!(upper, lower);
}
