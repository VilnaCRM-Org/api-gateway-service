use std::time::Duration;

use iam_domain::BootClock as _;

use super::LinuxBootClock;

#[test]
fn the_host_has_been_up_for_some_time() {
    assert!(LinuxBootClock.now().elapsed() > Duration::ZERO);
}

#[test]
fn the_clock_never_goes_backwards() {
    let clock = LinuxBootClock;
    let first = clock.now();
    let second = clock.now();

    assert!(second >= first);
    assert_eq!(first.saturating_since(second), Duration::ZERO);
}
