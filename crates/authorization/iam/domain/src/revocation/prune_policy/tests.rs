use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{CUTOFF_MARGIN, PrunePolicy};

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

#[test]
fn a_record_without_a_cutoff_is_kept_for_the_lifetime_the_skew_and_the_margin() {
    let policy = PrunePolicy::new(Duration::from_mins(30));

    assert_eq!(
        policy.prune_after(at(1_000), None),
        Some(at(1_000 + 1_800 + 120 + 60))
    );
}

#[test]
fn the_later_of_the_revocation_time_and_the_cutoff_instant_is_the_base() {
    let policy = PrunePolicy::new(Duration::from_mins(15));

    assert_eq!(
        policy.prune_after(at(1_000), Some(at(1_500))),
        Some(at(1_500 + 900 + 120 + 60))
    );
    assert_eq!(
        policy.prune_after(at(2_000), Some(at(1_500))),
        Some(at(2_000 + 900 + 120 + 60))
    );
}

#[test]
fn a_raised_lifetime_stays_in_force_for_the_next_record() {
    let raised = PrunePolicy::new(Duration::from_mins(30));

    assert_eq!(raised.longest_lifetime(), Duration::from_mins(30));
    assert_eq!(raised.prune_after(at(0), None), Some(at(1_980)));
}

#[test]
fn an_instant_that_overflows_is_none() {
    let policy = PrunePolicy::new(Duration::MAX);

    assert_eq!(policy.prune_after(at(1), None), None);
}

#[test]
fn the_cutoff_is_two_seconds_after_the_commit() {
    assert_eq!(CUTOFF_MARGIN, Duration::from_secs(2));
    assert_eq!(PrunePolicy::cutoff_at(at(10)), Some(at(12)));
}
