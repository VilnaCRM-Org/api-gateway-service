use rstest::rstest;

use super::RoleDescription;
use crate::error::InvalidRole;

#[rstest]
#[case::empty(String::new())]
#[case::several_lines("Manages invoices.\nReads payments.".to_owned())]
#[case::exactly_the_maximum("é".repeat(RoleDescription::MAX_CHARS))]
fn accepts_a_description_of_at_most_the_maximum_length(#[case] value: String) {
    assert_eq!(RoleDescription::new(value.clone()).unwrap().as_str(), value);
}

#[test]
fn rejects_one_character_more_than_the_maximum() {
    let value = "é".repeat(RoleDescription::MAX_CHARS + 1);

    assert_eq!(
        RoleDescription::new(value),
        Err(InvalidRole::DescriptionLength)
    );
}
