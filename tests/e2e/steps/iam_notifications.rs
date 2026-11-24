//! The steps that read the events topic of a scenario (Story 7.5): the events that the relay
//! published, their keys, their sizes and their fields, and the topics that IAM produced to.

use cucumber::then;
use serde_json::Value;

use crate::events_topic::EventRecord;
use crate::world::AppWorld;

/// The largest size of an envelope on the topic: 64 KiB.
const MAX_ENVELOPE_BYTES: usize = 65_536;

/// The topic of Notification service, which IAM never writes into.
const NOTIFICATIONS_TOPIC: &str = "notifications";

/// The records of the scenario's topic that carry `event_type`, in offset order.
fn of_type<'a>(records: &'a [EventRecord], event_type: &str) -> Vec<&'a EventRecord> {
    records
        .iter()
        .filter(|record| record.event_type() == event_type)
        .collect()
}

/// The only record of `event_type` on the scenario's topic.
///
/// # Panics
///
/// When the topic holds none or several.
fn only<'a>(records: &'a [EventRecord], event_type: &str) -> &'a EventRecord {
    let found = of_type(records, event_type);
    let [record] = found.as_slice() else {
        panic!("one {event_type} event on the topic, found {}", found.len());
    };
    record
}

/// The value of the JSON pointer `pointer` in the envelope of `record`.
fn value_at<'a>(record: &'a EventRecord, pointer: &str) -> &'a Value {
    record
        .envelope
        .pointer(pointer)
        .unwrap_or_else(|| panic!("the envelope holds {pointer}: {}", record.envelope))
}

#[then(expr = "the events topic of the scenario should hold {int} {string} event(s)")]
async fn topic_holds_events(world: &mut AppWorld, count: usize, event_type: String) {
    let records = world.scenario_events().await;
    assert_eq!(of_type(&records, &event_type).len(), count, "{records:?}");
}

#[then(expr = "the {string} event on the events topic should have {string} equal to {string}")]
async fn event_field_equals(
    world: &mut AppWorld,
    event_type: String,
    pointer: String,
    expected: String,
) {
    let records = world.scenario_events().await;
    let record = only(&records, &event_type);
    assert_eq!(
        value_at(record, &pointer),
        &Value::String(world.substitute(&expected))
    );
}

#[then(expr = "the {string} event on the events topic should have {string} present")]
async fn event_field_present(world: &mut AppWorld, event_type: String, pointer: String) {
    let records = world.scenario_events().await;
    let record = only(&records, &event_type);
    assert!(!value_at(record, &pointer).is_null(), "{pointer}");
}

#[then(expr = "the {string} event on the events topic should have {string} listing {string}")]
async fn event_field_lists(
    world: &mut AppWorld,
    event_type: String,
    pointer: String,
    expected: String,
) {
    let records = world.scenario_events().await;
    let record = only(&records, &event_type);
    let expected = Value::String(world.substitute(&expected));
    let listed = value_at(record, &pointer)
        .as_array()
        .unwrap_or_else(|| panic!("{pointer} is an array"));
    assert!(listed.contains(&expected), "{expected} in {listed:?}");
}

#[then(expr = "every {string} event on the events topic should be keyed by its aggregate id")]
async fn events_keyed_by_aggregate(world: &mut AppWorld, event_type: String) {
    let records = world.scenario_events().await;
    let found = of_type(&records, &event_type);
    assert!(!found.is_empty(), "an {event_type} event on the topic");
    for record in found {
        assert_eq!(
            &Value::String(record.key.clone()),
            value_at(record, "/data/aggregateId")
        );
    }
}

#[then("every envelope on the events topic should be at most 64 KiB")]
async fn envelopes_are_bounded(world: &mut AppWorld) {
    let records = world.scenario_events().await;
    assert!(!records.is_empty(), "the topic holds events");
    for record in &records {
        assert!(
            record.size > 0 && record.size <= MAX_ENVELOPE_BYTES,
            "{record:?}"
        );
    }
}

#[then("IAM should have produced only to the state topic and the events topic of the scenario")]
async fn iam_produced_to_two_topics(world: &mut AppWorld) {
    let records = world.scenario_events().await;
    assert!(!records.is_empty(), "the topic holds events");
    let events = world.scenario_topic_name().await;
    let state = AppWorld::state_topic();
    let produced = world.outbox_topics().await;
    assert!(
        produced
            .iter()
            .all(|topic| *topic == events || *topic == state),
        "the outbox names {produced:?}"
    );
    let broker = AppWorld::broker_topics().await;
    assert!(
        broker.contains(&events) && broker.contains(&state),
        "{broker:?}"
    );
    assert!(
        !broker.iter().any(|topic| topic == NOTIFICATIONS_TOPIC),
        "{broker:?}"
    );
}
