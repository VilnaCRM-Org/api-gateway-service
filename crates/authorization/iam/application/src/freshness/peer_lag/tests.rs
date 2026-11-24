use std::time::Duration;

use iam_domain::{BootInstant, PolicyVersion};

use super::{PEER_LAG_TOLERANCE, PeerLag, PeerLagTracker};

fn at(millis: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_millis(millis))
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn no_peer_ahead_is_no_lag() {
    let mut tracker = PeerLagTracker::new();

    assert_eq!(
        tracker.observe(at(0), version(5), &[version(5), version(4)]),
        PeerLag::None
    );
    assert_eq!(tracker.observe(at(0), version(5), &[]), PeerLag::None);
}

#[test]
fn a_peer_ahead_for_one_and_a_half_seconds_exceeds_the_tolerance() {
    let mut tracker = PeerLagTracker::new();
    let mut last = PeerLag::None;

    for millis in (0..=1_500).step_by(250) {
        last = tracker.observe(at(millis), version(5), &[version(6)]);
    }

    assert_eq!(
        last,
        PeerLag::Exceeded {
            lag: Duration::from_millis(1_500),
            peer: version(6),
            first: false,
        }
    );
}

#[test]
fn the_first_observation_beyond_the_tolerance_is_the_one_that_alerts() {
    let mut tracker = PeerLagTracker::new();
    tracker.observe(at(0), version(5), &[version(6)]);

    let first = tracker.observe(at(1_001), version(5), &[version(6)]);
    let second = tracker.observe(at(1_251), version(5), &[version(7)]);

    assert_eq!(
        first,
        PeerLag::Exceeded {
            lag: Duration::from_millis(1_001),
            peer: version(6),
            first: true,
        }
    );
    assert_eq!(
        second,
        PeerLag::Exceeded {
            lag: Duration::from_millis(1_251),
            peer: version(7),
            first: false,
        }
    );
}

#[test]
fn a_peer_ahead_for_half_a_second_is_within_the_tolerance() {
    let mut tracker = PeerLagTracker::new();

    tracker.observe(at(0), version(5), &[version(6)]);
    let within = tracker.observe(at(500), version(5), &[version(6)]);
    let caught_up = tracker.observe(at(750), version(6), &[version(6)]);
    let again = tracker.observe(at(2_000), version(6), &[version(7)]);

    assert_eq!(within, PeerLag::Ahead);
    assert_eq!(caught_up, PeerLag::None);
    assert_eq!(again, PeerLag::Ahead);
}

#[test]
fn the_tolerance_itself_is_not_exceeded() {
    let mut tracker = PeerLagTracker::new();
    tracker.observe(at(0), version(5), &[version(6)]);

    let observed = tracker.observe(
        at(u64::try_from(PEER_LAG_TOLERANCE.as_millis()).unwrap()),
        version(5),
        &[version(6)],
    );

    assert_eq!(observed, PeerLag::Ahead);
}
