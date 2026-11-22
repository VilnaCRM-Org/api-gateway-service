use rstest::rstest;

use super::RevocationSource;
use crate::error::InvalidIamValue;

#[rstest]
#[case(RevocationSource::UserService, "user-service")]
#[case(RevocationSource::Operator, "operator")]
fn the_text_form_round_trips(#[case] source: RevocationSource, #[case] text: &str) {
    assert_eq!(source.as_str(), text);
    assert_eq!(RevocationSource::parse(text), Ok(source));
}

#[rstest]
#[case("")]
#[case("Operator")]
#[case("user_service")]
fn any_other_text_is_refused(#[case] text: &str) {
    assert_eq!(
        RevocationSource::parse(text),
        Err(InvalidIamValue::RevocationSource)
    );
}
