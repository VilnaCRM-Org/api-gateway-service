use rstest::rstest;

use super::PropagationOutcome;

#[rstest]
#[case(PropagationOutcome::Published { offset: 7 })]
#[case(PropagationOutcome::CommittedPending)]
fn an_outcome_round_trips_through_its_stored_columns(#[case] outcome: PropagationOutcome) {
    assert_eq!(
        PropagationOutcome::restore(outcome.status(), outcome.offset()),
        Some(outcome)
    );
}

#[rstest]
#[case("published", None)]
#[case("unknown", Some(3))]
#[case("", None)]
fn unusable_columns_restore_no_outcome(#[case] status: &str, #[case] offset: Option<i64>) {
    assert_eq!(PropagationOutcome::restore(status, offset), None);
}

#[test]
fn only_a_published_outcome_is_published() {
    assert!(PropagationOutcome::Published { offset: 0 }.is_published());
    assert!(!PropagationOutcome::CommittedPending.is_published());
    assert_eq!(PropagationOutcome::CommittedPending.offset(), None);
}
