//! `KrafkaPolicyLogProducer` against the compose broker `kafka` (Story 7.4): the acknowledged
//! offsets of both modes, the fencing of an older transactional instance and the failure of a
//! cluster that cannot be reached.

use std::time::Duration;

use iam_domain::{
    ConfigGates, LogEpoch, OutboxKind, OutboxRow, PolicyDigestValue, PolicyLogError,
    PolicyLogProducer as _, PolicyLogRecord, PolicyVersion, RelayEpoch,
};
use iam_infrastructure::{KafkaSecurity, KafkaSettings, KrafkaPolicyLogProducer, RelayMode};
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

fn settings(bootstrap_servers: String) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers,
        security: KafkaSecurity::Plaintext,
        client_id: "iam-relay-integration-test".to_owned(),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Relaxed,
        policy_topic: "unused-policy-topic".to_owned(),
        events_topic: "unused-events-topic".to_owned(),
    }
}

fn compose_settings() -> KafkaSettings {
    settings(stack_variable("KAFKA_BOOTSTRAP_SERVERS"))
}

const TRANSACTIONAL: RelayMode = RelayMode::Transactional {
    transaction_timeout: Duration::from_secs(10),
};

/// A name no earlier run used: the compose broker keeps its topics and its transactional ids
/// between runs.
fn unique(label: &str) -> String {
    format!("iam-it-{label}-{}", UuidV7Generator.generate())
}

async fn create_topic(topic: &str, partitions: i32) {
    let kafka = Kafka::builder(stack_variable("KAFKA_BOOTSTRAP_SERVERS"))
        .client_id("iam-relay-integration-test-admin")
        .connect()
        .await
        .unwrap();
    let results = kafka
        .admin()
        .create_topics(
            [NewTopic::new(topic, partitions, 1).unwrap()],
            CreateTopicsOptions::default(),
        )
        .await
        .unwrap();
    drop(kafka);
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

fn state_row(topic: &str, key: &str, payload: Option<&str>, seq: u32) -> OutboxRow {
    OutboxRow {
        id: UuidV7Generator.generate(),
        kind: OutboxKind::State,
        topic: topic.to_owned(),
        record_key: key.to_owned(),
        payload: payload.map(str::to_owned),
        policy_version: PolicyVersion::new(1).unwrap(),
        seq: Some(seq),
        count: Some(3),
        digest_after: Some(PolicyDigestValue::ZERO),
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: None,
    }
}

fn records(topic: &str) -> Vec<PolicyLogRecord> {
    let epoch = RelayEpoch::new(1).unwrap();
    [
        state_row(topic, "role/a", Some("{}"), 1),
        state_row(topic, "role/b", None, 2),
        state_row(topic, "__head", Some("{}"), 3),
    ]
    .iter()
    .map(|row| PolicyLogRecord::of(row, epoch))
    .collect()
}

async fn published_offsets(mode: RelayMode) -> Vec<i64> {
    let topic = unique("state");
    create_topic(&topic, 1).await;
    let producer = KrafkaPolicyLogProducer::new(&compose_settings(), mode)
        .with_transactional_id(unique("relay"));

    producer.publish(&records(&topic)).await.unwrap()
}

#[tokio::test]
async fn the_epoch_only_producer_returns_consecutive_offsets_of_the_state_partition() {
    let offsets = published_offsets(RelayMode::EpochOnly).await;

    assert_eq!(offsets, [0, 1, 2]);
}

#[tokio::test]
async fn the_transactional_producer_returns_the_offsets_once_the_transaction_committed() {
    let offsets = published_offsets(TRANSACTIONAL).await;

    assert_eq!(offsets.len(), 3);
    assert!(offsets.windows(2).all(|pair| pair[1] > pair[0]));
}

#[tokio::test]
async fn a_second_batch_continues_after_the_first_in_the_same_partition() {
    let topic = unique("state");
    create_topic(&topic, 1).await;
    let producer = KrafkaPolicyLogProducer::new(&compose_settings(), RelayMode::EpochOnly);

    let first = producer.publish(&records(&topic)).await.unwrap();
    let second = producer.publish(&records(&topic)).await.unwrap();
    drop(producer);

    assert_eq!(
        first.last().map(|offset| offset + 1),
        second.first().copied()
    );
}

#[tokio::test]
async fn a_newer_transactional_instance_fences_the_older_one() {
    let topic = unique("state");
    create_topic(&topic, 1).await;
    let id = unique("relay");
    let older = KrafkaPolicyLogProducer::new(&compose_settings(), TRANSACTIONAL)
        .with_transactional_id(id.clone());
    older.publish(&records(&topic)).await.unwrap();
    let newer =
        KrafkaPolicyLogProducer::new(&compose_settings(), TRANSACTIONAL).with_transactional_id(id);
    newer.publish(&records(&topic)).await.unwrap();
    drop(newer);

    let late = older.publish(&records(&topic)).await;
    drop(older);

    assert!(matches!(late, Err(PolicyLogError::Fenced(_))), "{late:?}");
}

#[tokio::test]
async fn a_cluster_that_cannot_be_reached_is_unavailable() {
    let producer = KrafkaPolicyLogProducer::new(&settings("127.0.0.1:1".to_owned()), TRANSACTIONAL);

    let published = producer.publish(&records("any-topic")).await;
    drop(producer);

    assert!(matches!(published, Err(PolicyLogError::Unavailable(_))));
}

#[tokio::test]
async fn an_empty_batch_is_acknowledged_without_offsets() {
    let producer = KrafkaPolicyLogProducer::new(&compose_settings(), RelayMode::EpochOnly);

    let offsets = producer.publish(&[]).await.unwrap();
    drop(producer);

    assert_eq!(offsets.len(), 0);
}
