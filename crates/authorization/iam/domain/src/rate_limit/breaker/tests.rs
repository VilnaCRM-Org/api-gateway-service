use std::time::Duration;

use super::{BREAKER_FAILURE_THRESHOLD, BreakerPermit, StoreBreaker};
use crate::value_object::boot_instant::BootInstant;

const OPEN: Duration = Duration::from_secs(5);

fn at(seconds: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_secs(seconds))
}

fn opened_at(seconds: u64) -> StoreBreaker {
    let mut breaker = StoreBreaker::new(OPEN);
    for _ in 0..BREAKER_FAILURE_THRESHOLD {
        let permit = breaker.permit(at(seconds));
        breaker.record_failure(permit, at(seconds));
    }
    breaker
}

#[test]
fn a_new_breaker_lets_every_call_through() {
    let mut breaker = StoreBreaker::new(OPEN);

    assert_eq!(breaker.permit(at(0)), BreakerPermit::Call);
    assert_eq!(breaker.permit(at(0)), BreakerPermit::Call);
}

#[test]
fn the_fifth_consecutive_failure_opens_the_breaker_and_no_earlier_one_does() {
    let mut breaker = StoreBreaker::new(OPEN);

    for _ in 1..BREAKER_FAILURE_THRESHOLD {
        assert!(!breaker.record_failure(BreakerPermit::Call, at(1)));
    }
    assert_eq!(breaker.permit(at(1)), BreakerPermit::Call);
    assert!(breaker.record_failure(BreakerPermit::Call, at(1)));
    assert_eq!(breaker.permit(at(1)), BreakerPermit::Skip);
}

#[test]
fn an_answer_clears_the_failure_count() {
    let mut breaker = StoreBreaker::new(OPEN);
    for _ in 1..BREAKER_FAILURE_THRESHOLD {
        breaker.record_failure(BreakerPermit::Call, at(1));
    }
    breaker.record_success(BreakerPermit::Call);

    for _ in 1..BREAKER_FAILURE_THRESHOLD {
        assert!(!breaker.record_failure(BreakerPermit::Call, at(1)));
    }
    assert_eq!(breaker.permit(at(1)), BreakerPermit::Call);
}

#[test]
fn the_open_breaker_skips_until_its_duration_has_passed_then_lets_one_probe_through() {
    let mut breaker = opened_at(10);

    assert_eq!(breaker.permit(at(10)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(14)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(15)), BreakerPermit::Probe);
    assert_eq!(breaker.permit(at(15)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(16)), BreakerPermit::Skip);
}

#[test]
fn a_probe_that_succeeds_closes_the_breaker() {
    let mut breaker = opened_at(10);
    let probe = breaker.permit(at(15));

    breaker.record_success(probe);

    assert_eq!(breaker.permit(at(15)), BreakerPermit::Call);
    assert_eq!(breaker.permit(at(16)), BreakerPermit::Call);
}

#[test]
fn a_probe_that_fails_opens_the_breaker_for_another_full_duration() {
    let mut breaker = opened_at(10);
    let probe = breaker.permit(at(15));

    assert!(breaker.record_failure(probe, at(16)));

    assert_eq!(breaker.permit(at(20)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(21)), BreakerPermit::Probe);
}

#[test]
fn a_probe_whose_result_never_arrives_is_replaced_after_one_duration() {
    let mut breaker = opened_at(10);
    assert_eq!(breaker.permit(at(15)), BreakerPermit::Probe);

    assert_eq!(breaker.permit(at(19)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(20)), BreakerPermit::Probe);
}

#[test]
fn a_late_result_of_a_call_started_before_the_breaker_opened_changes_nothing() {
    let mut breaker = opened_at(10);

    breaker.record_success(BreakerPermit::Call);
    assert!(!breaker.record_failure(BreakerPermit::Call, at(11)));
    breaker.record_success(BreakerPermit::Skip);
    assert!(!breaker.record_failure(BreakerPermit::Skip, at(11)));

    assert_eq!(breaker.permit(at(14)), BreakerPermit::Skip);
    assert_eq!(breaker.permit(at(15)), BreakerPermit::Probe);
}

#[test]
fn a_duration_that_overflows_keeps_the_breaker_open() {
    let mut breaker = StoreBreaker::new(Duration::MAX);
    for _ in 0..BREAKER_FAILURE_THRESHOLD {
        breaker.record_failure(BreakerPermit::Call, at(1));
    }

    assert_eq!(breaker.permit(at(1_000_000)), BreakerPermit::Skip);
}
