use proptest::prelude::{ProptestConfig, any};
use rstest::rstest;

use super::ServiceName;
use crate::error::InvalidIamValue;

#[rstest]
#[case("a")]
#[case("iam")]
#[case("user-service")]
#[case("core2")]
#[case("a1-b2-c3")]
#[case("x-0")]
#[case("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk")]
fn accepts_a_lower_case_name_of_at_most_63_characters(#[case] value: &str) {
    let name = ServiceName::new(value).unwrap();

    assert_eq!(name.as_str(), value);
    assert_eq!(name.to_string(), value);
}

#[rstest]
#[case("")]
#[case("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl")]
fn rejects_an_empty_or_too_long_name(#[case] value: &str) {
    assert_eq!(
        ServiceName::new(value),
        Err(InvalidIamValue::ServiceNameLength)
    );
}

#[rstest]
#[case("1abc")]
#[case("-abc")]
#[case("abc-")]
#[case("a--b")]
#[case("User")]
#[case("user_service")]
#[case("user service")]
#[case("user.service")]
#[case("usér")]
#[case("*")]
fn rejects_a_name_of_the_wrong_shape(#[case] value: &str) {
    assert_eq!(
        ServiceName::new(value),
        Err(InvalidIamValue::ServiceNamePattern)
    );
}

#[test]
fn knows_the_iam_service() {
    assert_eq!(ServiceName::iam().as_str(), "iam");
    assert!(ServiceName::iam().is_iam());
    assert!(ServiceName::new("iam").unwrap().is_iam());
    assert!(!ServiceName::new("iam-control").unwrap().is_iam());
}

#[test]
fn names_are_ordered_by_their_text() {
    assert!(ServiceName::new("alpha").unwrap() < ServiceName::new("beta").unwrap());
}

/// Whether the text matches `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, written as a reference automaton.
fn matches_reference(value: &str) -> bool {
    let mut previous: Option<char> = None;
    for character in value.chars() {
        let allowed = match previous {
            None => character.is_ascii_lowercase(),
            Some('-') => character.is_ascii_lowercase() || character.is_ascii_digit(),
            Some(_) => {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            }
        };
        if !allowed {
            return false;
        }
        previous = Some(character);
    }
    previous.is_some_and(|last| last != '-')
}

proptest::proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn accepts_exactly_the_names_of_the_pattern_and_length(value in "[a-z0-9_-]{0,70}") {
        let expected = if value.is_empty() || value.len() > 63 {
            Err(InvalidIamValue::ServiceNameLength)
        } else if matches_reference(&value) {
            Ok(value.clone())
        } else {
            Err(InvalidIamValue::ServiceNamePattern)
        };

        proptest::prop_assert_eq!(
            ServiceName::new(&value).map(|name| name.as_str().to_owned()),
            expected
        );
    }

    #[test]
    fn never_accepts_text_outside_the_alphabet(value in any::<String>()) {
        let accepted = ServiceName::new(&value).is_ok();

        proptest::prop_assert_eq!(accepted, value.len() <= 63 && matches_reference(&value));
    }
}
