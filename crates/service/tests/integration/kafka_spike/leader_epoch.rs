//! Capability 4: `ListOffsets` carries `current_leader_epoch` (KIP-320), and a stale epoch, a future epoch
//! and an unavailable offset surface as distinguishable typed errors (`FENCED_LEADER_EPOCH`,
//! `UNKNOWN_LEADER_EPOCH`, `OFFSET_NOT_AVAILABLE`, KIP-207).
//!
//! The consumer's watermark lookup (`Consumer::fetch_watermarks`) sends `ListOffsets` with the leader epoch of
//! its cached metadata, answers with the broker's error code unchanged and refreshes the metadata afterwards,
//! so the caller sees a stale epoch once and the next lookup succeeds. A future epoch persists until the broker
//! catches up: the metadata refresh keeps the newer cached epoch (KIP-320 ignores an older epoch in a metadata
//! response), so every lookup answers `UNKNOWN_LEADER_EPOCH` until the broker reaches the client's epoch, and
//! the next lookup then succeeds. The `test-broker` checks the epoch the way
//! a broker does, so moving the broker's epoch past or behind the client's cached one makes the client send a
//! stale or a future epoch. The admin `list_offsets` call is not used: it retries these codes internally after
//! a metadata refresh and never shows them to the caller.

use krafka::error::ErrorCode;
use krafka::testing::{ApiKey, Control, FakeBroker};
use krafka::{Kafka, KrafkaError, Record};

use super::{PARTITION, compose_broker, create_topic, tail, unique_topic};

const TOPIC: &str = "iam-state";

/// The watermarks of [`TOPIC`] after [`broker_with_records`]: log start 0, high watermark 3.
const WATERMARKS: (i64, i64) = (0, 3);

/// Produces three records to partition 0 of `topic`.
async fn produce_three(kafka: &Kafka, topic: &str) {
    let producer = kafka.producer().build().await.unwrap();
    for value in ["0", "1", "2"] {
        let sent = producer
            .send(Record::new(topic, value).partition(PARTITION))
            .await
            .unwrap();
        assert_eq!(sent.partition, PARTITION);
    }
    producer.flush().await.unwrap();
    drop(producer);
}

/// A broker with three records on partition 0 of [`TOPIC`] at leader epoch 1, and a client whose metadata
/// cache holds that epoch.
async fn broker_with_records() -> (FakeBroker, Kafka) {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    assert!(broker.bump_leader_epoch(TOPIC, PARTITION));
    let kafka = broker.kafka().connect().await.unwrap();
    produce_three(&kafka, TOPIC).await;
    (broker, kafka)
}

/// The leader epoch of partition 0 of [`TOPIC`] on the broker.
fn broker_epoch(broker: &FakeBroker) -> Option<i32> {
    broker.with_state(|cluster| {
        cluster
            .partition(TOPIC, PARTITION)
            .map(|partition| partition.leader_epoch)
    })
}

/// Moves the broker's leader epoch of partition 0 of [`TOPIC`] one step back, behind the epoch the client
/// cached: the client then sends an epoch from the broker's future.
fn step_broker_epoch_back(broker: &FakeBroker) -> bool {
    broker.with_state(|cluster| match cluster.partition_mut(TOPIC, PARTITION) {
        Some(partition) => {
            partition.leader_epoch = partition.leader_epoch.checked_sub(1).unwrap();
            true
        }
        None => false,
    })
}

/// The broker error code of a failed lookup.
fn code(result: &Result<(i64, i64), KrafkaError>) -> Option<ErrorCode> {
    if let Err(KrafkaError::Broker { code, .. }) = result {
        Some(*code)
    } else {
        None
    }
}

#[tokio::test]
async fn list_offsets_with_the_current_leader_epoch_returns_the_high_watermark() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;

    let watermarks = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    drop(consumer);

    assert_eq!(watermarks.unwrap(), WATERMARKS);
    assert_eq!(broker_epoch(&broker), Some(1));
    assert!(broker.request_count(ApiKey::ListOffsets) >= 2);
}

#[tokio::test]
async fn list_offsets_with_a_stale_leader_epoch_surfaces_fenced_leader_epoch() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    let current = consumer.fetch_watermarks(TOPIC, PARTITION).await;

    assert!(broker.bump_leader_epoch(TOPIC, PARTITION));
    let fault = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    let recovered = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    drop(consumer);

    assert_eq!(current.unwrap(), WATERMARKS);
    assert_eq!(
        code(&fault),
        Some(ErrorCode::FencedLeaderEpoch),
        "{fault:?}"
    );
    assert_eq!(recovered.unwrap(), WATERMARKS);
}

#[tokio::test]
async fn list_offsets_with_a_future_leader_epoch_surfaces_unknown_leader_epoch() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    let current = consumer.fetch_watermarks(TOPIC, PARTITION).await;

    assert!(step_broker_epoch_back(&broker));
    let fault = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    let still_ahead = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    assert!(broker.bump_leader_epoch(TOPIC, PARTITION));
    let recovered = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    drop(consumer);

    assert_eq!(current.unwrap(), WATERMARKS);
    assert_eq!(
        code(&fault),
        Some(ErrorCode::UnknownLeaderEpoch),
        "{fault:?}"
    );
    assert_eq!(
        code(&still_ahead),
        Some(ErrorCode::UnknownLeaderEpoch),
        "{still_ahead:?}"
    );
    assert_eq!(recovered.unwrap(), WATERMARKS);
}

#[tokio::test]
async fn an_injected_offset_not_available_surfaces_as_its_own_typed_error() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    broker.on(ApiKey::ListOffsets, |_| {
        Control::Error(ErrorCode::OffsetNotAvailable)
    });

    let fault = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    broker.clear_hooks();
    let recovered = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    drop(consumer);

    assert_eq!(
        code(&fault),
        Some(ErrorCode::OffsetNotAvailable),
        "{fault:?}"
    );
    assert!(fault.as_ref().is_err_and(KrafkaError::is_retriable));
    assert_eq!(recovered.unwrap(), WATERMARKS);
}

#[test]
fn the_three_epoch_and_offset_errors_are_distinct_retriable_codes() {
    let codes = [
        ErrorCode::FencedLeaderEpoch,
        ErrorCode::UnknownLeaderEpoch,
        ErrorCode::OffsetNotAvailable,
    ];

    assert!(codes.iter().all(ErrorCode::is_retriable));
    assert_ne!(codes[0], codes[1]);
    assert_ne!(codes[1], codes[2]);
    assert_ne!(codes[0], codes[2]);
}

#[tokio::test]
async fn the_compose_broker_answers_list_offsets_with_the_current_epoch_with_the_high_watermark() {
    let kafka = compose_broker().await;
    let topic = unique_topic("epoch");
    create_topic(&kafka, &topic).await;
    produce_three(&kafka, &topic).await;
    let consumer = tail(&kafka, &topic, 0).await;

    let watermarks = consumer.fetch_watermarks(&topic, PARTITION).await;
    drop(consumer);

    assert_eq!(watermarks.unwrap(), WATERMARKS);
}
