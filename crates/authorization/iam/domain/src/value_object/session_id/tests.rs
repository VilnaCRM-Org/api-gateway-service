use rstest::rstest;

use super::SessionId;
use crate::value_object::token_rejection::TokenRejection;

#[rstest]
#[case("a")]
#[case("0190f2a8-7b3c-7d4e-8f10-1234567890ab")]
#[case(&"x".repeat(255))]
fn accepts_one_to_255_visible_ascii_characters(#[case] value: &str) {
    let id = SessionId::new(value).unwrap();

    assert_eq!(id.as_str(), value);
    assert_eq!(id.to_string(), value);
}

#[rstest]
#[case("")]
#[case(&"x".repeat(256))]
#[case("with space")]
#[case("ünicode")]
fn rejects_empty_long_or_invisible_text_as_an_invalid_token(#[case] value: &str) {
    assert_eq!(SessionId::new(value), Err(TokenRejection::Invalid));
}
