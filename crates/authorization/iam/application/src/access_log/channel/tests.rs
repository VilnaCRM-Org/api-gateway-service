use std::sync::Arc;
use std::time::Duration;

use iam_domain::{AccessClass, AccessLane};

use super::{Received, access_log_channel};
use crate::access_log::counters::AccessLogCounters;
use crate::access_log::fixtures::{decision_id, error_item, item, unavailable};

#[test]
fn an_offered_item_reaches_the_receiver_in_order() {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, receiver) = access_log_channel(8, counters);

    channel.offer(error_item(1, 100, 503));
    channel.offer(error_item(2, 100, 503));

    let first = receiver.try_next().unwrap();
    let second = receiver.try_next().unwrap();
    assert_eq!(first.record.decision_id, decision_id(1));
    assert_eq!(second.record.decision_id, decision_id(2));
    assert!(receiver.try_next().is_none());
}

#[test]
fn a_full_channel_drops_the_item_without_waiting_and_counts_it_by_lane_and_class() {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, _receiver) = access_log_channel(2, Arc::clone(&counters));
    channel.offer(error_item(1, 100, 503));
    channel.offer(error_item(2, 100, 503));

    for counter in 3..1_003 {
        channel.offer(error_item(counter, 100, 503));
    }
    channel.offer(item(AccessLane::Audit, AccessClass::Audit, unavailable()));

    assert_eq!(
        counters.dropped_count(AccessLane::Access, AccessClass::Error),
        1_000
    );
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        1
    );
}

#[test]
fn a_writer_that_is_gone_makes_every_offer_a_counted_drop() {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, receiver) = access_log_channel(2, Arc::clone(&counters));
    drop(receiver);

    channel.offer(error_item(1, 100, 503));

    assert_eq!(
        counters.dropped_count(AccessLane::Access, AccessClass::Error),
        1
    );
}

#[test]
fn the_receiver_tells_an_idle_channel_from_a_closed_one() {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, receiver) = access_log_channel(2, counters);

    assert_eq!(receiver.receive(Duration::from_millis(1)), Received::Idle);
    channel.offer(error_item(1, 100, 503));
    assert!(matches!(
        receiver.receive(Duration::from_millis(1)),
        Received::Item(_)
    ));
    drop(channel);
    assert_eq!(receiver.receive(Duration::from_millis(1)), Received::Closed);
}
