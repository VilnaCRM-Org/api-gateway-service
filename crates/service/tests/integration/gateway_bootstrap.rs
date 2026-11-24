//! The bootstrap of a gateway pod against the compose broker (Story 9.3): the pod rebuilds the
//! policy from the state topic under the bootstrap principal, publishes the version before an
//! incomplete trailing version, and stays not started after one retry when a record carries a
//! version above the highest complete head.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iam_domain::{
    ConfigGates, FramedRecord, LogEpoch, OutboxKind, OutboxRow, PolicyBootstrapLog,
    PolicyDigestValue, PolicyHead, PolicyLogProducer as _, PolicyLogRecord, PolicyLogTailError,
    PolicyState, PolicyVersion, PolicyView as _, RelayEpoch, StateRecordCodec as _,
};
use iam_infrastructure::{
    JsonStateRecordCodec, KafkaSecurity, KafkaSettings, KrafkaPolicyLogProducer,
    KrafkaPolicyLogTail, RelayMode,
};
use krafka::Kafka;
use krafka::admin::{CreateTopicsOptions, NewTopic};
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;
use test_support::boot_clock::FakeBootClock;
use tokio::sync::watch;

use crate::support::stack_variable;
use service::bootstrap::gateway::policy::{PolicyAdapters, start_policy};
use service::bootstrap::{TaskMode, TaskStop, TaskSupervisor};

const BOUND: Duration = Duration::from_secs(20);
const ROLE_KEY: &str = "role/0192f6a0-0000-7000-8000-000000000001";

fn settings(topic: &str) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: stack_variable("KAFKA_BOOTSTRAP_SERVERS"),
        security: KafkaSecurity::Plaintext,
        client_id: "iam-gateway-bootstrap".to_owned(),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Relaxed,
        policy_topic: topic.to_owned(),
        events_topic: "unused-events-topic".to_owned(),
    }
}

fn unique_topic() -> String {
    format!("iam-it-gateway-bootstrap-{}", UuidV7Generator.generate())
}

fn row(
    topic: &str,
    key: &str,
    payload: Option<String>,
    version: i64,
    framing: (u32, u32),
) -> OutboxRow {
    OutboxRow {
        id: UuidV7Generator.generate(),
        kind: OutboxKind::State,
        topic: topic.to_owned(),
        record_key: key.to_owned(),
        payload,
        policy_version: PolicyVersion::new(version).unwrap(),
        seq: Some(framing.0),
        count: Some(framing.1),
        digest_after: Some(PolicyDigestValue::ZERO),
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: None,
    }
}

/// The head of an empty policy at `version`: it is the only row of its version.
fn empty_head(topic: &str, version: i64) -> OutboxRow {
    let head = PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(version).unwrap(),
        digest: PolicyDigestValue::ZERO,
    });
    let payload = JsonStateRecordCodec.encode(&head).unwrap();
    row(topic, "__head", Some(payload), version, (1, 1))
}

/// Creates the state topic with one partition: the compose broker does not create topics on
/// first use, so a producer would wait for its metadata forever.
async fn create_topic(topic: &str) {
    let kafka = Kafka::builder(stack_variable("KAFKA_BOOTSTRAP_SERVERS"))
        .client_id("iam-gateway-bootstrap-admin")
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

/// Creates the topic and publishes the rows in one relay transaction, within [`BOUND`].
async fn publish(topic: &str, rows: &[OutboxRow]) {
    let records: Vec<_> = rows
        .iter()
        .map(|row| PolicyLogRecord::of(row, RelayEpoch::new(1).unwrap()))
        .collect();
    let published = tokio::time::timeout(BOUND, async {
        create_topic(topic).await;
        KrafkaPolicyLogProducer::new(
            &settings(topic),
            RelayMode::Transactional {
                transaction_timeout: Duration::from_secs(10),
            },
        )
        .with_transactional_id(format!("iam-it-relay-{}", UuidV7Generator.generate()))
        .publish(&records)
        .await
        .unwrap();
    })
    .await;
    assert!(published.is_ok(), "the records were not published in time");
}

/// The bootstrap connection that counts how often the pod captured the stable end.
#[derive(Debug)]
struct CountingLog {
    inner: KrafkaPolicyLogTail,
    captures: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl PolicyBootstrapLog for CountingLog {
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        PolicyBootstrapLog::stable_end(&self.inner).await
    }

    async fn read_framed(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<FramedRecord>, PolicyLogTailError> {
        PolicyBootstrapLog::read_framed(&self.inner, from, up_to).await
    }

    async fn close(&self) {
        PolicyBootstrapLog::close(&self.inner).await;
    }
}

fn adapters(topic: &str) -> (PolicyAdapters, Arc<AtomicUsize>) {
    let captures = Arc::new(AtomicUsize::new(0));
    let log = CountingLog {
        inner: KrafkaPolicyLogTail::bootstrap(settings(topic)),
        captures: Arc::clone(&captures),
    };
    (
        PolicyAdapters::with(Arc::new(log), Arc::new(FakeBootClock::new())),
        captures,
    )
}

/// Bootstraps a pod on `topic` and returns the published version, if the pod started.
async fn bootstrap(topic: &str) -> (Option<PolicyVersion>, usize) {
    let (adapters, captures) = adapters(topic);
    let (stop, stopping) = watch::channel(false);
    let mut tasks = TaskSupervisor::new(TaskMode::Test, stopping);
    let death = start_policy(&adapters, &mut tasks).unwrap();
    let started = tokio::time::timeout(BOUND, async {
        while adapters.cell.current().is_none() && captures.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Give a failing bootstrap time to finish its retry before it is judged.
        tokio::time::sleep(Duration::from_millis(500)).await;
    })
    .await;
    assert!(started.is_ok(), "the bootstrap did not settle in time");
    let version = adapters.cell.current().map(|snapshot| snapshot.version());
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, TaskStop::Drained);
    drop(death);
    (version, captures.load(Ordering::SeqCst))
}

#[tokio::test]
async fn a_pod_publishes_the_highest_complete_head_of_the_topic() {
    let topic = unique_topic();
    publish(&topic, &[empty_head(&topic, 1)]).await;

    let (version, _captures) = bootstrap(&topic).await;

    assert_eq!(version, Some(PolicyVersion::new(1).unwrap()));
}

#[tokio::test]
async fn a_relay_stopped_in_the_middle_of_a_version_leaves_the_pod_on_the_version_before_it() {
    let topic = unique_topic();
    publish(
        &topic,
        &[
            empty_head(&topic, 1),
            row(&topic, ROLE_KEY, None, 2, (1, 2)),
        ],
    )
    .await;

    let (version, _captures) = bootstrap(&topic).await;

    assert_eq!(version, Some(PolicyVersion::new(1).unwrap()));
}

#[tokio::test]
async fn a_record_above_the_highest_head_leaves_the_pod_not_started_after_one_retry() {
    let topic = unique_topic();
    publish(
        &topic,
        &[
            empty_head(&topic, 1),
            row(&topic, ROLE_KEY, None, 3, (1, 2)),
        ],
    )
    .await;

    let (version, captures) = bootstrap(&topic).await;

    assert_eq!(version, None);
    assert_eq!(captures, 2, "one first attempt and exactly one retry");
}
