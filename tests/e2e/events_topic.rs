//! The events topic of a scenario on the compose broker (Story 7.5).
//!
//! Scenarios run concurrently and every one of them has its own database, so a shared
//! `iam.events.v1` would mix their events. Each scenario creates a topic of its own, with the
//! settings of the compose topic, points `EVENTS_TOPIC` at it and reads it back with a consumer that
//! holds no group and sees committed records only.

use std::time::Duration;

use krafka::Kafka;
use krafka::admin::{CreateTopicsOptions, DeleteTopicsOptions, ListTopicsOptions, NewTopic};
use krafka::consumer::{AutoOffsetReset, IsolationLevel};
use serde_json::Value;
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;

/// The only partition of an events topic.
const PARTITION: i32 = 0;

/// How long one poll waits for records.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a read waits for the consumer to reach the end of the topic.
const DEADLINE: Duration = Duration::from_secs(30);

/// The settings of the compose events topic (`scripts/kafka-topics-fixture.sh`).
const SETTINGS: [(&str, &str); 4] = [
    ("cleanup.policy", "delete"),
    ("min.insync.replicas", "1"),
    ("unclean.leader.election.enable", "false"),
    ("message.timestamp.type", "LogAppendTime"),
];

/// One record of an events topic: its key and its envelope.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EventRecord {
    pub(crate) key: String,
    pub(crate) size: usize,
    pub(crate) envelope: Value,
}

impl EventRecord {
    /// The `type` of the envelope.
    pub(crate) fn event_type(&self) -> &str {
        self.envelope
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// A topic name no earlier run used: the compose broker keeps its topics between runs.
pub(crate) fn unique_name() -> String {
    format!("iam.events.e2e.{}", UuidV7Generator.generate())
}

async fn connect(bootstrap_servers: &str) -> Kafka {
    Kafka::builder(bootstrap_servers.to_owned())
        .client_id("iam-e2e-events")
        .connect()
        .await
        .expect("the compose broker is reachable")
}

/// Creates the topic `name` with the settings of the compose events topic.
pub(crate) async fn create(bootstrap_servers: &str, name: &str) {
    let kafka = connect(bootstrap_servers).await;
    let topic = SETTINGS.iter().fold(
        NewTopic::new(name, 1, 1).expect("a valid topic"),
        |topic, (setting, value)| topic.with_config(*setting, *value),
    );
    let created = kafka
        .admin()
        .create_topics([topic], CreateTopicsOptions::default())
        .await
        .expect("create the scenario topic");
    drop(kafka);
    assert!(matches!(created.get(name), Some(Ok(()))), "{created:?}");
}

/// Deletes the topic `name`; a topic that stays only costs the broker some disk.
pub(crate) async fn delete(bootstrap_servers: &str, name: &str) {
    let kafka = connect(bootstrap_servers).await;
    let deleted = kafka
        .admin()
        .delete_topics([name], DeleteTopicsOptions::default())
        .await;
    drop(kafka);
    drop(deleted);
}

/// Every committed record of the topic, in offset order.
pub(crate) async fn read(bootstrap_servers: &str, name: &str) -> Vec<EventRecord> {
    let kafka = connect(bootstrap_servers).await;
    let consumer = kafka
        .consumer_without_group()
        .isolation_level(IsolationLevel::ReadCommitted)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .enable_auto_commit(false)
        .build()
        .await
        .expect("open a consumer");
    consumer
        .assign(name, vec![PARTITION])
        .await
        .expect("assign the topic");
    let (_low, end) = consumer
        .fetch_watermarks(name, PARTITION)
        .await
        .expect("the watermarks of the topic");
    consumer
        .seek(name, PARTITION, 0)
        .await
        .expect("seek to the start");
    let mut records = Vec::new();
    let mut polls = DEADLINE
        .as_millis()
        .checked_div(POLL_TIMEOUT.as_millis())
        .unwrap_or(1);
    while polls > 0 && consumer.position(name, PARTITION).await.unwrap_or(0) < end {
        polls = polls.saturating_sub(1);
        for record in consumer.poll(POLL_TIMEOUT).await.expect("poll the topic") {
            records.push(EventRecord {
                key: record.key_str().unwrap_or_default().to_owned(),
                size: record.value_str().map_or(0, str::len),
                envelope: serde_json::from_str(record.value_str().unwrap_or("null"))
                    .unwrap_or(Value::Null),
            });
        }
    }
    consumer.close().await.expect("close the consumer");
    drop(consumer);
    drop(kafka);
    records
}

/// The names of the topics of the broker.
pub(crate) async fn topics(bootstrap_servers: &str) -> Vec<String> {
    let kafka = connect(bootstrap_servers).await;
    let listed = kafka
        .admin()
        .list_topics(ListTopicsOptions::default())
        .await
        .expect("list the topics");
    drop(kafka);
    listed
}
