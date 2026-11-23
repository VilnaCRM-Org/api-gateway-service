use std::time::Duration;

use rstest::rstest;

use super::RateDecision;

#[test]
fn an_admitted_request_has_no_wait() {
    assert!(RateDecision::Admit.is_admitted());
    assert_eq!(RateDecision::Admit.retry_after(), None);
    assert_eq!(RateDecision::Admit.retry_after_seconds(), None);
}

#[rstest]
#[case::exact_seconds(Duration::from_secs(3), 3)]
#[case::rounded_up(Duration::from_millis(2_001), 3)]
#[case::one_nanosecond(Duration::from_nanos(1), 1)]
#[case::zero_is_at_least_one(Duration::ZERO, 1)]
#[case::sub_second(Duration::from_millis(600), 1)]
fn a_rejected_request_waits_whole_seconds_rounded_up(#[case] wait: Duration, #[case] seconds: u64) {
    let decision = RateDecision::Reject { retry_after: wait };

    assert!(!decision.is_admitted());
    assert_eq!(decision.retry_after(), Some(wait));
    assert_eq!(decision.retry_after_seconds(), Some(seconds));
}
