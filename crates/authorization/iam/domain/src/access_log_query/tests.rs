use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::{
    AccessLogCursor, AccessLogRange, ID_WINDOW_NANOS, InvalidAccessLogRange, NANOS_PER_MILLI,
};

const DAY: Duration = Duration::from_hours(24);

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

#[test]
fn a_range_within_the_limit_keeps_its_bounds_in_nanoseconds() {
    let range = AccessLogRange::new(at(100), at(200), DAY).unwrap();

    assert_eq!(range.start_nanos(), 100_000_000_000);
    assert_eq!(range.until_nanos(), 200_000_000_000);
}

#[test]
fn a_range_of_exactly_the_limit_is_accepted() {
    assert!(AccessLogRange::new(at(0), at(86_400), DAY).is_ok());
}

#[rstest]
#[case::longer(at(0), at(86_401), InvalidAccessLogRange::TooLong)]
#[case::empty(at(5), at(5), InvalidAccessLogRange::Inverted)]
#[case::inverted(at(9), at(5), InvalidAccessLogRange::Inverted)]
fn a_range_that_cannot_be_queried_is_refused(
    #[case] from: SystemTime,
    #[case] until: SystemTime,
    #[case] expected: InvalidAccessLogRange,
) {
    assert_eq!(AccessLogRange::new(from, until, DAY), Err(expected));
}

#[test]
fn a_bound_before_1970_is_out_of_bounds() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();

    assert_eq!(
        AccessLogRange::new(before, at(5), DAY),
        Err(InvalidAccessLogRange::OutOfBounds)
    );
}

#[test]
fn a_violation_names_its_property_and_code() {
    assert_eq!(InvalidAccessLogRange::OutOfBounds.property_path(), "from");
    assert_eq!(InvalidAccessLogRange::TooLong.property_path(), "until");
    assert_eq!(InvalidAccessLogRange::Inverted.property_path(), "until");
    assert_eq!(InvalidAccessLogRange::OutOfBounds.code(), "range_bounds");
    assert_eq!(InvalidAccessLogRange::Inverted.code(), "range_inverted");
    assert_eq!(InvalidAccessLogRange::TooLong.code(), "range_too_long");
}

#[test]
fn the_window_of_a_uuid_v7_spans_two_seconds_around_its_millisecond() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();
    let millis = 0x0190_f2a8_7b3c_u64;

    let window = AccessLogRange::around(id).unwrap();

    assert_eq!(
        window.start_nanos(),
        millis * NANOS_PER_MILLI - ID_WINDOW_NANOS
    );
    assert_eq!(
        window.until_nanos(),
        millis * NANOS_PER_MILLI + NANOS_PER_MILLI + ID_WINDOW_NANOS
    );
}

#[test]
fn an_id_that_is_not_a_uuid_v7_has_no_window() {
    let v4 = Uuid::parse("5f1c2d3e-4b5a-4c6d-8e7f-0123456789ab").unwrap();

    assert_eq!(AccessLogRange::around(v4), None);
}

#[test]
fn a_range_that_continues_a_page_ends_one_nanosecond_after_the_last_entry() {
    let range = AccessLogRange::new(at(100), at(200), DAY).unwrap();

    let next = range.ending_at(150_000_000_000);

    assert_eq!(next.start_nanos(), 100_000_000_000);
    assert_eq!(next.until_nanos(), 150_000_000_001);
}

#[test]
fn a_range_never_grows_when_it_continues_a_page() {
    let range = AccessLogRange::new(at(100), at(200), DAY).unwrap();

    assert_eq!(range.ending_at(u64::MAX), range);
}

#[test]
fn a_cursor_round_trips_through_its_text() {
    let cursor = AccessLogCursor {
        timestamp_nanos: 1_700_000_000_123_456_789,
        returned: 42,
    };

    assert_eq!(AccessLogCursor::parse(&cursor.encode()), Some(cursor));
}

#[rstest]
#[case::empty("")]
#[case::no_separator("abc")]
#[case::missing_count("abc.")]
#[case::missing_time(".1")]
#[case::not_hexadecimal("xyz.1")]
#[case::signed("-1.1")]
#[case::too_large("ffffffffffffffffff.1")]
#[case::count_too_large("1.ffffffffff")]
fn a_text_that_is_not_a_cursor_is_refused(#[case] text: &str) {
    assert_eq!(AccessLogCursor::parse(text), None);
}

#[rstest]
#[case::new_timestamp(Some((10, 3)), 20, 2, 2)]
#[case::same_timestamp(Some((20, 3)), 20, 2, 5)]
#[case::first_page(None, 20, 4, 4)]
fn the_cursor_after_a_page_counts_the_entries_at_its_last_timestamp(
    #[case] previous: Option<(u64, u32)>,
    #[case] last: u64,
    #[case] in_page: u32,
    #[case] returned: u32,
) {
    let previous = previous.map(|(timestamp_nanos, returned)| AccessLogCursor {
        timestamp_nanos,
        returned,
    });

    assert_eq!(
        AccessLogCursor::after(last, in_page, previous),
        AccessLogCursor {
            timestamp_nanos: last,
            returned,
        }
    );
}
