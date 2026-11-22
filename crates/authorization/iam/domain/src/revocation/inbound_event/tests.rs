use rstest::rstest;

use super::InboundOutcome;
use crate::error::InvalidIamValue;

#[rstest]
#[case(InboundOutcome::Applied, "applied")]
#[case(InboundOutcome::Ignored, "ignored")]
#[case(InboundOutcome::DeadLetter, "dead_letter")]
fn the_text_form_round_trips(#[case] outcome: InboundOutcome, #[case] text: &str) {
    assert_eq!(outcome.as_str(), text);
    assert_eq!(InboundOutcome::parse(text), Ok(outcome));
}

#[rstest]
#[case("")]
#[case("Applied")]
#[case("dead-letter")]
fn any_other_text_is_refused(#[case] text: &str) {
    assert_eq!(
        InboundOutcome::parse(text),
        Err(InvalidIamValue::InboundOutcome)
    );
}
