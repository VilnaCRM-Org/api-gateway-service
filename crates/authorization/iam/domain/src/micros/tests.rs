use std::time::{Duration, SystemTime};

use super::{since_epoch, time_of};

#[test]
fn a_time_after_1970_round_trips_through_whole_microseconds() {
    let time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_nanos(1_700_000_000_123_456_789))
        .unwrap();

    let micros = since_epoch(time).unwrap();

    assert_eq!(micros, 1_700_000_000_123_456);
    assert_eq!(
        time_of(micros),
        Some(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_micros(1_700_000_000_123_456))
                .unwrap()
        )
    );
}

#[test]
fn a_time_before_1970_or_a_negative_count_has_no_microseconds() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();

    assert_eq!(since_epoch(before), None);
    assert_eq!(time_of(-1), None);
}

#[test]
fn a_time_past_the_largest_count_has_no_microseconds() {
    let far = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(u64::MAX))
        .unwrap();

    assert_eq!(since_epoch(far), None);
}
