use rstest::rstest;

use super::AuditOutcome;
use crate::error::InvalidIamValue;

#[rstest]
#[case("committed", AuditOutcome::Committed)]
#[case("rejected", AuditOutcome::Rejected)]
fn an_outcome_round_trips_through_its_name(#[case] text: &str, #[case] outcome: AuditOutcome) {
    assert_eq!(AuditOutcome::parse(text), Ok(outcome));
    assert_eq!(outcome.as_str(), text);
}

#[rstest]
#[case("")]
#[case("Committed")]
#[case("denied")]
fn rejects_any_other_text(#[case] text: &str) {
    assert_eq!(
        AuditOutcome::parse(text),
        Err(InvalidIamValue::AuditOutcome)
    );
}
