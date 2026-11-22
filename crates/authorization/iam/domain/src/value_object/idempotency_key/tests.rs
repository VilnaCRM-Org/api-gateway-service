use rstest::rstest;

use super::IdempotencyKey;
use crate::error::InvalidIamValue;

#[rstest]
#[case("k")]
#[case("8e03978e-40d5-43e8-bc93-6894a57f9324")]
#[case(&"k".repeat(255))]
fn accepts_one_to_255_visible_ascii_characters(#[case] value: &str) {
    let key = IdempotencyKey::new(value).unwrap();

    assert_eq!(key.as_str(), value);
    assert_eq!(key.to_string(), value);
}

#[rstest]
#[case("")]
#[case(&"k".repeat(256))]
#[case("with space")]
#[case("line\nbreak")]
fn rejects_empty_long_or_invisible_text(#[case] value: &str) {
    assert_eq!(
        IdempotencyKey::new(value),
        Err(InvalidIamValue::IdempotencyKeyFormat)
    );
}
