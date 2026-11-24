use sqlx::types::time::OffsetDateTime;

use super::micros_of;

#[test]
fn a_stored_time_becomes_whole_microseconds_since_1970() {
    let time = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();

    assert_eq!(micros_of(time).unwrap(), 1_700_000_000_123_456);
}

#[test]
fn a_time_before_1970_is_unusable() {
    let time = OffsetDateTime::from_unix_timestamp(-1).unwrap();

    assert!(micros_of(time).is_err());
}
