use super::{AntiEntropyCounters, TopicAheadHold};

#[test]
fn the_hold_is_set_and_released() {
    let hold = TopicAheadHold::new();
    assert!(!hold.is_set());

    hold.set(true);
    assert!(hold.is_set());

    hold.set(false);
    assert!(!hold.is_set());
}

#[test]
fn the_counter_counts_every_record() {
    let counters = AntiEntropyCounters::new();

    counters.record();
    counters.record();

    assert_eq!(counters.repairs_total(), 2);
}
