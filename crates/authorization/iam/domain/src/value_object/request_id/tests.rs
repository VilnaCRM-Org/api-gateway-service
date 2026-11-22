use rstest::rstest;

use super::RequestId;
use crate::error::InvalidIamValue;

#[rstest]
#[case("r")]
#[case("req-0190f2a8:7b3c/1")]
#[case(&"x".repeat(128))]
fn accepts_one_to_128_visible_ascii_characters(#[case] value: &str) {
    let id = RequestId::new(value).unwrap();

    assert_eq!(id.as_str(), value);
    assert_eq!(id.to_string(), value);
}

#[rstest]
#[case("")]
#[case(&"x".repeat(129))]
#[case("with space")]
#[case("tab\there")]
#[case("ünicode")]
fn rejects_empty_long_or_invisible_text(#[case] value: &str) {
    assert_eq!(RequestId::new(value), Err(InvalidIamValue::RequestIdFormat));
}
