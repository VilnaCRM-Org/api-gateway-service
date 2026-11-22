//! Phase-0 spike of Story 1.2: krafka's tail without a consumer group (capabilities 1, 2 and 10 of
//! `architecture.md` section 20).
//!
//! The tests record the client behaviour the replication design rests on; no production crate depends on
//! krafka, and the module leaves in Story 1.7. The tests against the compose broker read
//! `KAFKA_BOOTSTRAP_SERVERS` (`.env.test`); the fault tests run against krafka's in-process `test-broker`,
//! whose hooks inject an open transaction, a dropped connection and broker errors deterministically. The
//! results are recorded in `docs/spikes/phase-0.md`.

#[cfg(test)]
mod headers;
#[cfg(test)]
mod out_of_range;
#[cfg(test)]
mod read_committed;
#[cfg(test)]
mod reconnect;
#[cfg(test)]
mod typed_errors;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use krafka::admin::{CreateTopicsOptions, NewTopic};
use krafka::consumer::{AutoOffsetReset, Consumer, ConsumerBuilder, IsolationLevel};
use krafka::{ConsumerRecord, Kafka, KrafkaError};
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;

use crate::support::stack_variable;

/// The one partition the policy log uses.
pub(crate) const PARTITION: i32 = 0;

/// One long poll of the tail.
pub(crate) const POLL: Duration = Duration::from_millis(300);

/// Upper bound for reading the records a test expects; a test that reaches it fails on its assertion.
pub(crate) const DEADLINE: Duration = Duration::from_secs(30);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// The bootstrap address of the compose broker `kafka`.
pub(crate) fn bootstrap_servers() -> String {
    stack_variable("KAFKA_BOOTSTRAP_SERVERS")
}

/// A topic name no earlier run used: the compose broker keeps its topics between runs.
pub(crate) fn unique_topic(label: &str) -> String {
    let number = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let id = UuidV7Generator.generate();
    format!("iam-spike-{label}-{id}-{number}")
}

/// A client of the compose broker.
pub(crate) async fn compose_broker() -> Kafka {
    Kafka::builder(bootstrap_servers())
        .client_id("iam-spike")
        .connect()
        .await
        .unwrap()
}

/// Creates a one-partition topic with one replica on the compose broker.
pub(crate) async fn create_topic(kafka: &Kafka, topic: &str) {
    let results = kafka
        .admin()
        .create_topics(
            [NewTopic::new(topic, 1, 1).unwrap()],
            CreateTopicsOptions::default(),
        )
        .await
        .unwrap();
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

/// The tail of the replication design: no consumer group, `read_committed`, never an automatic offset
/// reset, `fetch.min.bytes` 1 and a 100 ms fetch wait (FR-71).
pub(crate) fn tail_builder(kafka: &Kafka) -> ConsumerBuilder {
    kafka
        .consumer_without_group()
        .isolation_level(IsolationLevel::ReadCommitted)
        .auto_offset_reset(AutoOffsetReset::None)
        .enable_auto_commit(false)
        .fetch_min_bytes(1)
        .fetch_max_wait(Duration::from_millis(100))
}

/// Builds the tail, assigns partition 0 by hand and starts it at `position`, as the gateway's tail starts
/// at its in-memory position.
pub(crate) async fn start_tail(builder: ConsumerBuilder, topic: &str, position: i64) -> Consumer {
    let consumer = builder.build().await.unwrap();
    consumer.assign(topic, vec![PARTITION]).await.unwrap();
    consumer.seek(topic, PARTITION, position).await.unwrap();
    consumer
}

/// The tail of [`tail_builder`] started at `position`.
pub(crate) async fn tail(kafka: &Kafka, topic: &str, position: i64) -> Consumer {
    start_tail(tail_builder(kafka), topic, position).await
}

/// Polls until `count` records arrived or [`DEADLINE`] elapsed; a poll error fails the test.
pub(crate) async fn read(consumer: &Consumer, count: usize) -> Vec<ConsumerRecord> {
    let started = tokio::time::Instant::now();
    let mut records = Vec::new();
    while records.len() < count && started.elapsed() < DEADLINE {
        records.extend(consumer.poll(POLL).await.unwrap());
    }
    records
}

/// Polls until the first error, the first records or [`DEADLINE`]: the error a fault surfaces, or what the
/// tail read instead.
pub(crate) async fn first_error(consumer: &Consumer) -> Result<Vec<ConsumerRecord>, KrafkaError> {
    let started = tokio::time::Instant::now();
    let mut records = Vec::new();
    while records.is_empty() && started.elapsed() < DEADLINE {
        records.extend(consumer.poll(POLL).await?);
    }
    Ok(records)
}

/// Polls `times` more times and returns what arrived: the "nothing else is readable" check.
pub(crate) async fn settle(consumer: &Consumer, times: usize) -> Vec<ConsumerRecord> {
    let mut records = Vec::new();
    for _ in 0..times {
        records.extend(consumer.poll(POLL).await.unwrap());
    }
    records
}

/// The values of `records` as text, in the order they were read.
pub(crate) fn values(records: &[ConsumerRecord]) -> Vec<Option<String>> {
    records
        .iter()
        .map(|record| record.value_str().map(str::to_owned))
        .collect()
}

/// The offsets of `records`, in the order they were read.
pub(crate) fn offsets(records: &[ConsumerRecord]) -> Vec<i64> {
    records.iter().map(|record| record.offset).collect()
}
