use std::sync::Arc;
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootInstant, Freshness, FreshnessRule, PolicyVersion, StaleCause};
use test_support::boot_clock::FakeBootClock;

use super::FreshnessState;

const HARD: Duration = Duration::from_secs(15);
const READY: Duration = Duration::from_secs(2);

fn state() -> (FreshnessState, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = FreshnessState::new(
        FreshnessRule::new(HARD, READY),
        Arc::<FakeBootClock>::clone(&clock),
    );
    (state, clock)
}

fn proof_at(clock: &FakeBootClock) -> FreshnessProof {
    use iam_domain::BootClock as _;
    FreshnessProof {
        taken_at: clock.now(),
        watermark: 5,
    }
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn holds_no_proof_at_first() {
    let (state, _clock) = state();

    assert_eq!(state.stale_cause(), Some(StaleCause::NoProof));
    assert!(!state.is_fresh());
    assert_eq!(state.reading().proof_age, None);
    assert_eq!(state.reading().proven_version, None);
}

#[test]
fn is_fresh_up_to_the_hard_bound_and_stale_a_millisecond_later() {
    let (state, clock) = state();
    state.attach(proof_at(&clock), version(3));

    clock.advance(HARD);
    assert!(state.is_fresh());
    assert_eq!(state.reading().proof_age, Some(HARD));
    assert_eq!(state.reading().proven_version, Some(version(3)));

    clock.advance(Duration::from_millis(1));
    assert_eq!(
        state.verdict(),
        Freshness::Stale(StaleCause::Aged(Duration::from_millis(15_001)))
    );
}

#[test]
fn a_jump_larger_than_the_ready_bound_invalidates_the_proof_until_a_new_one_is_attached() {
    let (state, clock) = state();
    assert_eq!(state.tick(), None);
    state.attach(proof_at(&clock), version(3));

    clock.jump(READY + Duration::from_millis(1));
    assert_eq!(state.tick(), Some(READY + Duration::from_millis(1)));
    assert_eq!(
        state.stale_cause(),
        Some(StaleCause::Gap(READY + Duration::from_millis(1)))
    );

    clock.advance(Duration::from_millis(1));
    state.attach(proof_at(&clock), version(4));
    assert!(state.is_fresh());
}

#[test]
fn small_gaps_do_not_invalidate_the_proof() {
    let (state, clock) = state();
    state.tick();
    state.attach(proof_at(&clock), version(3));

    for _ in 0..5 {
        clock.advance(Duration::from_secs(1));
        state.tick();
    }

    assert!(state.is_fresh());
}

#[test]
fn a_proof_attached_after_a_long_silence_of_the_watchdog_is_stale_at_once() {
    let (state, clock) = state();
    state.tick();
    clock.advance(READY + Duration::from_secs(1));

    state.attach(proof_at(&clock), version(3));

    assert!(!state.is_fresh());
}

#[test]
fn invalidate_withdraws_the_proof() {
    let (state, clock) = state();
    state.attach(proof_at(&clock), version(3));

    state.invalidate();

    assert_eq!(state.stale_cause(), Some(StaleCause::NoProof));
    assert_eq!(state.reading().proven_version, None);
}

#[test]
fn a_fresh_pod_has_no_stale_cause() {
    let (state, clock) = state();
    state.attach(proof_at(&clock), version(3));

    assert_eq!(state.stale_cause(), None);
}

#[test]
fn a_proof_taken_before_an_invalidation_is_refused() {
    let (state, clock) = state();
    let early = proof_at(&clock);
    clock.advance(Duration::from_millis(5));
    state.invalidate();

    assert!(!state.attach(early, version(3)));

    assert_eq!(state.stale_cause(), Some(StaleCause::NoProof));
    assert_eq!(state.reading().proven_version, None);
}

#[test]
fn a_proof_taken_at_the_instant_of_an_invalidation_is_refused_and_a_later_one_accepted() {
    let (state, clock) = state();
    state.invalidate();

    assert!(!state.attach(proof_at(&clock), version(3)));

    clock.advance(Duration::from_millis(1));
    assert!(state.attach(proof_at(&clock), version(3)));
    assert!(state.is_fresh());
}

#[test]
fn a_proof_taken_before_a_gap_above_the_ready_bound_is_refused() {
    let (state, clock) = state();
    state.tick();
    let early = proof_at(&clock);
    clock.jump(READY + Duration::from_millis(1));
    state.tick();

    assert!(!state.attach(early, version(3)));
    assert_eq!(state.stale_cause(), Some(StaleCause::NoProof));

    clock.advance(Duration::from_millis(1));
    assert!(state.attach(proof_at(&clock), version(3)));
    assert!(state.is_fresh());
}

#[test]
fn a_proof_taken_before_the_watchdog_was_found_silent_is_refused() {
    let (state, clock) = state();
    state.tick();
    let early = proof_at(&clock);
    clock.advance(READY + Duration::from_secs(1));

    assert!(!state.attach(early, version(3)));
    assert!(!state.attach(proof_at(&clock), version(3)));
    assert!(!state.is_fresh());
}

#[test]
fn a_gap_within_the_ready_bound_after_the_proof_still_counts_for_the_verdict() {
    let (state, clock) = state();
    state.tick();
    clock.advance(Duration::from_millis(1));
    assert!(state.attach(proof_at(&clock), version(3)));
    state.tick();

    clock.advance(READY);
    state.tick();
    assert!(state.is_fresh());

    clock.advance(READY + Duration::from_millis(1));
    state.tick();
    assert_eq!(
        state.stale_cause(),
        Some(StaleCause::Gap(READY + Duration::from_millis(1)))
    );
}
