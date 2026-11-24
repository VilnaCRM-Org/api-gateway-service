//! `KrafkaPolicyLogTail` against the compose broker `kafka` (Story 7.7): the watermark, the bounded
//! range reads, the read at one offset, a transaction marker that holds no record, and the failure
//! of a cluster that cannot be reached.

use std::time::Duration;

use iam_domain::{
    ConfigGates, LogEpoch, OutboxKind, OutboxRow, PolicyDigestValue, PolicyLogProducer as _,
    PolicyLogRecord, PolicyLogTail as _, PolicyLogTailError, PolicyVersion, RelayEpoch,
};
use iam_infrastructure::{
    KafkaSecurity, KafkaSettings, KrafkaPolicyLogProducer, KrafkaPolicyLogTail, RelayMode,
};
use krafka::Kafka;
use krafka::admin::{CreateTopicsOptions, NewTopic};
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;

#[expect(
    clippy::disallowed_methods,
    reason = "the test stack is described by the environment"
)]
fn stack_variable(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run the tests through `make`"))
}

fn settings(bootstrap_servers: String, topic: &str) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers,
        security: KafkaSecurity::Plaintext,
        client_id: "iam-tail-integration-test".to_owned(),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Relaxed,
        policy_topic: topic.to_owned(),
        events_topic: "unused-events-topic".to_owned(),
    }
}

fn unique(label: &str) -> String {
    format!("iam-it-{label}-{}", UuidV7Generator.generate())
}

async fn create_topic(topic: &str) {
    let kafka = Kafka::builder(stack_variable("KAFKA_BOOTSTRAP_SERVERS"))
        .client_id("iam-tail-integration-test-admin")
        .connect()
        .await
        .unwrap();
    let results = kafka
        .admin()
        .create_topics(
            [NewTopic::new(topic, 1, 1).unwrap()],
            CreateTopicsOptions::default(),
        )
        .await
        .unwrap();
    drop(kafka);
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

fn row(topic: &str, key: &str, payload: Option<&str>, version: i64, seq: u32) -> OutboxRow {
    OutboxRow {
        id: UuidV7Generator.generate(),
        kind: OutboxKind::State,
        topic: topic.to_owned(),
        record_key: key.to_owned(),
        payload: payload.map(str::to_owned),
        policy_version: PolicyVersion::new(version).unwrap(),
        seq: Some(seq),
        count: Some(3),
        digest_after: Some(PolicyDigestValue::ZERO),
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: None,
    }
}

/// Publishes three records through the transactional producer and returns the topic and the
/// offsets.
async fn topic_with_records() -> (String, KafkaSettings, Vec<i64>) {
    let topic = unique("tail");
    create_topic(&topic).await;
    let settings = settings(stack_variable("KAFKA_BOOTSTRAP_SERVERS"), &topic);
    let epoch = RelayEpoch::new(2).unwrap();
    let records: Vec<_> = [
        row(&topic, "role/a", Some("{\"a\":1}"), 4, 1),
        row(&topic, "role/b", None, 4, 2),
        row(&topic, "__head", Some("{}"), 4, 3),
    ]
    .iter()
    .map(|row| PolicyLogRecord::of(row, epoch))
    .collect();
    let offsets = KrafkaPolicyLogProducer::new(
        &settings,
        RelayMode::Transactional {
            transaction_timeout: Duration::from_secs(10),
        },
    )
    .with_transactional_id(unique("relay"))
    .publish(&records)
    .await
    .unwrap();
    (topic, settings, offsets)
}

#[tokio::test]
async fn the_range_returns_the_records_with_their_framing_up_to_the_watermark() {
    let (_topic, settings, offsets) = topic_with_records().await;
    let tail = KrafkaPolicyLogTail::new(settings);

    let watermark = tail.watermark().await.unwrap();
    let records = tail.read_range(0, watermark).await.unwrap();
    drop(tail);

    assert!(watermark > *offsets.last().unwrap());
    let keys: Vec<_> = records.iter().map(|record| record.key.as_str()).collect();
    assert_eq!(keys, ["role/a", "role/b", "__head"]);
    assert_eq!(records[0].payload.as_deref(), Some("{\"a\":1}"));
    assert_eq!(records[1].payload, None);
    assert_eq!(records[0].version.value(), 4);
    assert_eq!(records[0].relay_epoch.value(), 2);
    assert_eq!(records[0].offset, offsets[0]);
}

#[tokio::test]
async fn a_closed_reader_opens_a_new_connection_for_its_next_read() {
    let (_topic, settings, offsets) = topic_with_records().await;
    let tail = KrafkaPolicyLogTail::new(settings);
    tail.close().await;

    let first = tail.read_at(offsets[0]).await.unwrap();
    tail.close().await;
    let second = tail.read_at(offsets[0]).await.unwrap();
    tail.close().await;
    drop(tail);

    assert_eq!(first.unwrap().key, "role/a");
    assert_eq!(second.unwrap().key, "role/a");
}

#[tokio::test]
async fn a_range_stops_before_its_end() {
    let (_topic, settings, offsets) = topic_with_records().await;
    let records = KrafkaPolicyLogTail::new(settings)
        .read_range(offsets[1], offsets[2])
        .await
        .unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key, "role/b");
}

#[tokio::test]
async fn the_record_at_one_offset_is_read_and_an_offset_past_the_end_holds_none() {
    let (_topic, settings, offsets) = topic_with_records().await;
    let tail = KrafkaPolicyLogTail::new(settings);

    let found = tail.read_at(offsets[2]).await.unwrap();
    let missing = tail.read_at(offsets[2] + 100).await.unwrap();
    drop(tail);

    assert_eq!(found.unwrap().key, "__head");
    assert_eq!(missing, None);
}

#[tokio::test]
async fn an_empty_range_reads_nothing() {
    let (_topic, settings, _offsets) = topic_with_records().await;
    let records = KrafkaPolicyLogTail::new(settings)
        .read_range(5, 5)
        .await
        .unwrap();

    assert_eq!(records.len(), 0);
}

#[tokio::test]
async fn a_cluster_that_cannot_be_reached_is_unavailable() {
    let mut unreachable = settings("127.0.0.1:1".to_owned(), "unused");
    unreachable.connect_timeout = Duration::from_millis(300);
    unreachable.request_timeout = Duration::from_millis(300);
    let tail = KrafkaPolicyLogTail::new(unreachable);

    assert!(matches!(
        tail.watermark().await,
        Err(PolicyLogTailError::Unavailable(_))
    ));
    assert!(matches!(
        tail.read_range(0, 10).await,
        Err(PolicyLogTailError::Unavailable(_))
    ));
    drop(tail);
}
