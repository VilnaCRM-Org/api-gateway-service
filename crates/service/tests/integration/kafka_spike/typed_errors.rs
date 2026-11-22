//! Capability 10: injected `OFFSET_OUT_OF_RANGE`, `NOT_LEADER_OR_FOLLOWER` and request-timeout faults reach
//! the reader as distinguishable typed errors.
//!
//! A `Fetch` answered with `OFFSET_OUT_OF_RANGE` fails the poll with `NoOffset`. `NOT_LEADER_OR_FOLLOWER` and
//! a request timeout on a `Fetch` are retried inside krafka (a metadata refresh and a back-off) and never fail
//! the poll; the reader meets them as typed errors on its `ListOffsets` watermark lookup, which the tail and
//! the probe send. The last test records the `Fetch` behaviour.

use std::time::Duration;

use krafka::error::ErrorCode;
use krafka::testing::{ApiKey, Control, FakeBroker};
use krafka::{Kafka, KrafkaError, Record};

use super::{PARTITION, first_error, read, tail, values};

const TOPIC: &str = "iam-policy-log";

/// A broker with three committed records on partition 0 of [`TOPIC`], and a client of it whose requests time
/// out after one second.
async fn broker_with_records() -> (FakeBroker, Kafka) {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker
        .kafka()
        .connect_timeout(Duration::from_millis(500))
        .request_timeout(Duration::from_secs(1))
        .connect()
        .await
        .unwrap();
    let producer = kafka.producer().build().await.unwrap();
    for value in ["0", "1", "2"] {
        let sent = producer
            .send(Record::new(TOPIC, value).partition(PARTITION))
            .await
            .unwrap();
        assert_eq!(sent.partition, PARTITION);
    }
    producer.flush().await.unwrap();
    drop(producer);
    (broker, kafka)
}

fn all_values() -> Vec<Option<String>> {
    ["0", "1", "2"].map(|value| Some(value.to_owned())).to_vec()
}

#[tokio::test]
async fn offset_out_of_range_on_fetch_fails_the_poll_with_no_offset_and_keeps_the_position() {
    let (broker, kafka) = broker_with_records().await;
    broker.on_once(ApiKey::Fetch, |_| {
        Control::Error(ErrorCode::OffsetOutOfRange)
    });
    let consumer = tail(&kafka, TOPIC, 0).await;

    let fault = first_error(&consumer).await;
    let position = consumer.position(TOPIC, PARTITION).await;
    let after = read(&consumer, 3).await;
    drop(consumer);

    assert!(
        matches!(&fault, Err(KrafkaError::NoOffset { partitions }) if partitions == &[(TOPIC.to_owned(), PARTITION)]),
        "{fault:?}"
    );
    assert_eq!(position, Some(0));
    assert_eq!(values(&after), all_values());
}

#[tokio::test]
async fn not_leader_or_follower_on_the_watermark_lookup_is_a_typed_broker_error() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    broker.on(ApiKey::ListOffsets, |_| {
        Control::Error(ErrorCode::NotLeaderForPartition)
    });

    let fault = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    broker.clear_hooks();
    let recovered = consumer.fetch_watermarks(TOPIC, PARTITION).await;
    drop(consumer);

    assert!(
        matches!(
            &fault,
            Err(KrafkaError::Broker {
                code: ErrorCode::NotLeaderForPartition,
                ..
            })
        ),
        "{fault:?}"
    );
    assert!(fault.as_ref().is_err_and(KrafkaError::is_retriable));
    assert_eq!(recovered.unwrap(), (0, 3));
}

#[tokio::test]
async fn a_request_timeout_on_the_watermark_lookup_is_a_typed_timeout() {
    let (broker, kafka) = broker_with_records().await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    broker.on(ApiKey::ListOffsets, |_| Control::Silence);

    let fault = tokio::time::timeout(
        Duration::from_secs(10),
        consumer.fetch_watermarks(TOPIC, PARTITION),
    )
    .await
    .unwrap();
    drop(consumer);
    broker.clear_hooks();

    assert!(
        matches!(&fault, Err(KrafkaError::Timeout { .. })),
        "{fault:?}"
    );
}

#[tokio::test]
async fn not_leader_and_a_timeout_on_fetch_are_retried_inside_krafka_without_loss() {
    let (broker, kafka) = broker_with_records().await;
    broker.on_once(ApiKey::Fetch, |_| {
        Control::Error(ErrorCode::NotLeaderForPartition)
    });
    broker.on_once(ApiKey::Fetch, |_| Control::Silence);
    let consumer = tail(&kafka, TOPIC, 0).await;

    let records = read(&consumer, 3).await;
    drop(consumer);

    assert_eq!(values(&records), all_values());
    assert!(broker.request_count(ApiKey::Fetch) >= 3);
}
