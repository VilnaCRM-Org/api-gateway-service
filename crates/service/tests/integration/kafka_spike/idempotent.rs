//! Capability 6: the relay's idempotent producer writes the state topic exactly once and in order across
//! retriable errors.
//!
//! The producer is the one FR-46 describes: `acks=all`, idempotence on, lz4, an explicit partition 0 and
//! the `iam-*` framing headers. krafka has no `max.in.flight.requests.per.connection` setting: its send
//! engine keeps at most one batch per partition on the wire, which is the one-request-in-flight bound of
//! FR-46 for the state topic's single partition.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use krafka::producer::{Acks, DeliveryHandle, Producer, ProducerBuilder};
use krafka::testing::{ApiKey, Control, FakeBroker};
use krafka::{Compression, ConsumerRecord, Kafka, Record};

use super::{PARTITION, compose_broker, create_topic, read, tail, unique_topic, values};

const TOPIC: &str = "iam-state";
const RECORDS: u32 = 10_000;
/// Small batches, so that the 10,000 records take many `Produce` requests and many of them meet a fault.
const BATCH_BYTES: usize = 4 * 1024;
/// Every fifth `Produce` request is answered with a fault.
const FAULT_EVERY: u32 = 5;
/// The compression codec attribute of a stored record batch: byte 21 and 22 of the batch header.
const ATTRIBUTES: std::ops::Range<usize> = 21..23;
const CODEC_MASK: u8 = 0x07;
const LZ4: u8 = 3;

/// The relay's idempotent producer of FR-46.
fn relay_builder(kafka: &Kafka) -> ProducerBuilder {
    kafka
        .producer()
        .acks(Acks::All)
        .idempotent(true)
        .compression(Compression::Lz4)
}

fn state_record(topic: &str, sequence: u32) -> Record {
    Record::new(topic.to_owned(), sequence.to_string())
        .key("row")
        .partition(PARTITION)
        .header("iam-seq", sequence.to_be_bytes().to_vec())
        .header("iam-op", "upsert")
}

/// The fault a `Produce` request meets: the write lands but the answer is lost (the retry must be
/// de-duplicated), the write is refused with `NOT_LEADER_OR_FOLLOWER`, or the write lands and is answered
/// with `REQUEST_TIMED_OUT`.
fn fault(request: u32) -> Control {
    match request
        .checked_div(FAULT_EVERY)
        .and_then(|n| n.checked_rem(3))
    {
        Some(0) => Control::ApplyThen(Box::new(Control::Disconnect)),
        Some(1) => Control::Error(krafka::error::ErrorCode::NotLeaderForPartition),
        _ => Control::ApplyThen(Box::new(Control::Error(
            krafka::error::ErrorCode::RequestTimedOut,
        ))),
    }
}

/// Answers every [`FAULT_EVERY`]th `Produce` request with a [`fault`] and counts the faults injected.
fn inject_produce_faults(broker: &FakeBroker) -> Arc<AtomicU32> {
    let requests = Arc::new(AtomicU32::new(0));
    let injected = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&injected);
    broker.on(ApiKey::Produce, move |_| {
        let request = requests.fetch_add(1, Ordering::Relaxed);
        if request.checked_rem(FAULT_EVERY) == Some(1) {
            counted.fetch_add(1, Ordering::Relaxed);
            fault(request)
        } else {
            Control::Pass
        }
    });
    injected
}

async fn enqueue_all(producer: &Producer, topic: &str) -> Vec<DeliveryHandle> {
    let mut handles = Vec::new();
    for sequence in 0..RECORDS {
        handles.push(
            producer
                .enqueue(state_record(topic, sequence))
                .await
                .unwrap(),
        );
    }
    handles
}

/// The compression codec of every batch the broker stored for partition 0.
fn stored_codecs(broker: &FakeBroker, topic: &str) -> Vec<u8> {
    broker.with_state(|cluster| {
        cluster
            .partition(topic, PARTITION)
            .map(|partition| {
                partition
                    .log
                    .iter()
                    .filter_map(|batch| batch.get(ATTRIBUTES))
                    .filter_map(|attributes| attributes.get(1))
                    .map(|low| low & CODEC_MASK)
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn sequences(records: &[ConsumerRecord]) -> Vec<Option<Vec<u8>>> {
    records
        .iter()
        .map(|record| {
            record
                .header("iam-seq")
                .flatten()
                .map(|value| value.to_vec())
        })
        .collect()
}

fn expected_values() -> Vec<Option<String>> {
    (0..RECORDS).map(|n| Some(n.to_string())).collect()
}

fn expected_sequences() -> Vec<Option<Vec<u8>>> {
    (0..RECORDS)
        .map(|n| Some(n.to_be_bytes().to_vec()))
        .collect()
}

#[tokio::test]
async fn retried_writes_of_ten_thousand_records_land_exactly_once_in_order_with_contiguous_offsets()
{
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker.kafka().connect().await.unwrap();
    let producer = relay_builder(&kafka)
        .batch_size(BATCH_BYTES)
        .retry_backoff(Duration::from_millis(5))
        .build()
        .await
        .unwrap();
    let injected = inject_produce_faults(&broker);

    let handles = enqueue_all(&producer, TOPIC).await;
    producer.flush().await.unwrap();
    let mut returned = Vec::new();
    for handle in handles {
        returned.push(handle.await.unwrap());
    }
    producer.close().await.unwrap();
    drop(producer);
    broker.clear_hooks();
    let stored = broker.all_records(TOPIC).unwrap();

    assert!(injected.load(Ordering::Relaxed) >= 3, "{injected:?}");
    assert!(returned.iter().all(|sent| sent.partition == PARTITION));
    let returned_offsets: Vec<i64> = returned.iter().map(|sent| sent.offset).collect();
    assert_eq!(
        returned_offsets,
        (0..i64::from(RECORDS)).collect::<Vec<_>>()
    );
    assert_eq!(
        stored
            .iter()
            .map(|record| record.offset)
            .collect::<Vec<_>>(),
        returned_offsets
    );
    assert_eq!(values(&stored), expected_values());
    assert_eq!(sequences(&stored), expected_sequences());
    let codecs = stored_codecs(&broker, TOPIC);
    assert!(codecs.len() > 1, "{codecs:?}");
    assert!(codecs.iter().all(|codec| *codec == LZ4), "{codecs:?}");
}

#[tokio::test]
async fn the_compose_broker_accepts_and_returns_lz4_batches_of_the_idempotent_producer() {
    let kafka = compose_broker().await;
    let topic = unique_topic("idempotent");
    create_topic(&kafka, &topic).await;
    let producer = relay_builder(&kafka).build().await.unwrap();

    let first = producer.send(state_record(&topic, 0)).await.unwrap();
    let second = producer.send(state_record(&topic, 1)).await.unwrap();
    producer.close().await.unwrap();
    drop(producer);
    let consumer = tail(&kafka, &topic, 0).await;
    let records = read(&consumer, 2).await;
    drop(consumer);

    assert_eq!((first.partition, second.partition), (PARTITION, PARTITION));
    assert_eq!(second.offset, first.offset.checked_add(1).unwrap());
    assert_eq!(
        values(&records),
        [Some("0".to_owned()), Some("1".to_owned())]
    );
    assert_eq!(
        sequences(&records),
        [
            Some(0_u32.to_be_bytes().to_vec()),
            Some(1_u32.to_be_bytes().to_vec())
        ]
    );
}
