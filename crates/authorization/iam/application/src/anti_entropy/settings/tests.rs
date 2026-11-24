use std::time::Duration;

use super::{AntiEntropySettings, InvalidAntiEntropySettings};

#[test]
fn the_defaults_are_five_seconds_and_ten_minutes() {
    let settings = AntiEntropySettings::default();

    assert_eq!(settings.head_interval(), Duration::from_secs(5));
    assert_eq!(settings.full_interval(), Duration::from_mins(10));
}

#[test]
fn a_zero_head_interval_is_refused() {
    let refused = AntiEntropySettings::new(Duration::ZERO, Duration::from_mins(1));

    assert_eq!(refused, Err(InvalidAntiEntropySettings::HeadInterval));
}

#[test]
fn a_zero_full_interval_is_refused() {
    let refused = AntiEntropySettings::new(Duration::from_secs(5), Duration::ZERO);

    assert_eq!(refused, Err(InvalidAntiEntropySettings::FullInterval));
}

#[test]
fn a_full_interval_shorter_than_the_head_interval_is_refused() {
    let refused = AntiEntropySettings::new(Duration::from_secs(10), Duration::from_secs(9));

    assert_eq!(refused, Err(InvalidAntiEntropySettings::FullInterval));
}

#[test]
fn equal_intervals_are_accepted() {
    let settings =
        AntiEntropySettings::new(Duration::from_secs(10), Duration::from_secs(10)).unwrap();

    assert_eq!(settings.full_interval(), Duration::from_secs(10));
}
