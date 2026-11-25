use std::sync::Arc;
use std::time::Duration;

use test_support::clock::ManualClock;

use super::AuditGate;
use crate::access_log::fixtures::at;

fn gate(max_pending: Duration, capacity: usize) -> (AuditGate, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::at(at(1_800_000_000)));
    let gate = AuditGate::new(Arc::<ManualClock>::clone(&clock), max_pending, capacity);
    (gate, clock)
}

#[test]
fn a_gate_with_nothing_pending_admits() {
    let (gate, _clock) = gate(Duration::from_secs(5), 10);

    assert!(gate.admits());
    assert_eq!(gate.pending(), 0);
    assert_eq!(gate.oldest_wait(), Duration::ZERO);
    assert_eq!(gate.capacity(), 10);
}

#[test]
fn an_entry_that_waits_longer_than_the_bound_closes_the_gate_and_an_acknowledgement_opens_it() {
    let (gate, clock) = gate(Duration::from_secs(5), 10);
    gate.publish(1, Some(at(1_800_000_000)));

    clock.advance(Duration::from_secs(5));
    assert!(gate.admits());
    clock.advance(Duration::from_millis(1));
    assert!(!gate.admits());
    assert_eq!(gate.oldest_wait(), Duration::from_millis(5_001));

    gate.publish(0, None);
    assert!(gate.admits());
}

#[test]
fn a_gate_whose_pending_entries_reach_the_capacity_is_closed() {
    let (gate, _clock) = gate(Duration::from_secs(5), 2);

    gate.publish(1, Some(at(1_800_000_000)));
    assert!(gate.admits());
    gate.publish(2, Some(at(1_800_000_000)));
    assert!(!gate.admits());
}

#[test]
fn a_full_channel_closes_the_gate_until_the_writer_takes_a_record() {
    let (gate, _clock) = gate(Duration::from_secs(5), 10);

    gate.mark_channel_full();
    assert!(!gate.admits());
    gate.clear_channel_full();
    assert!(gate.admits());
}

#[test]
fn an_entry_from_the_future_does_not_count_as_waiting() {
    let (gate, _clock) = gate(Duration::from_secs(1), 10);

    gate.publish(1, Some(at(1_800_000_100)));

    assert_eq!(gate.oldest_wait(), Duration::ZERO);
    assert!(gate.admits());
}
