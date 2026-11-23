use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    LeaderBatch, LogEpoch, OutboxKind, OutboxRow, PolicyDigestValue, PolicyLogRecord,
    PolicyVersion, RelayEpoch, RepositoryError, Violation,
};
use shared_domain::{BoxError, Uuid};
use test_support::clock::ManualClock;
use test_support::outbox_store::{Failing, FakeOutboxStore};
use test_support::policy_log_producer::{Answer, FakePolicyLogProducer};
use test_support::singleton_leadership::{FakeSingletonLeadership, Step};
use test_support::topic_inspector::FakeTopicInspector;
use tokio::sync::{Notify, watch};

use super::{
    IncompleteAcknowledgement, OutboxRelay, OutboxRelayPorts, OutboxRelaySettings, POLL_INTERVAL,
};
use crate::singleton_loop::{BatchOutcome, SingletonWork as _};

/// A batch that holds no transaction.
#[derive(Debug)]
struct NullBatch;

#[async_trait::async_trait]
impl LeaderBatch for NullBatch {
    async fn record_run(&mut self, _at: SystemTime) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RepositoryError> {
        Ok(())
    }
}

fn start() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn row(number: u32) -> OutboxRow {
    OutboxRow {
        id: Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012}")).unwrap(),
        kind: OutboxKind::State,
        topic: "iam.policy.state.v1".to_owned(),
        record_key: format!("role/{number}"),
        payload: Some("{}".to_owned()),
        policy_version: PolicyVersion::new(1).unwrap(),
        seq: Some(number),
        count: Some(number),
        digest_after: Some(PolicyDigestValue::ZERO),
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: None,
    }
}

struct Rig {
    relay: OutboxRelay,
    store: Arc<FakeOutboxStore>,
    producer: Arc<FakePolicyLogProducer>,
    inspector: Arc<FakeTopicInspector>,
    clock: Arc<ManualClock>,
    leading: watch::Receiver<bool>,
}

fn rig(
    store: FakeOutboxStore,
    producer: FakePolicyLogProducer,
    inspector: FakeTopicInspector,
    settings: OutboxRelaySettings,
) -> Rig {
    let store = Arc::new(store);
    let producer = Arc::new(producer);
    let inspector = Arc::new(inspector);
    let clock = Arc::new(ManualClock::at(start()));
    let (sender, leading) = watch::channel(false);
    let relay = OutboxRelay::new(
        OutboxRelayPorts {
            store: Arc::<FakeOutboxStore>::clone(&store),
            producer: Arc::<FakePolicyLogProducer>::clone(&producer),
            inspector: Arc::<FakeTopicInspector>::clone(&inspector),
        },
        Arc::<ManualClock>::clone(&clock),
        settings,
        Arc::new(sender),
    );
    Rig {
        relay,
        store,
        producer,
        inspector,
        clock,
        leading,
    }
}

fn simple(rows: Vec<OutboxRow>) -> Rig {
    rig(
        FakeOutboxStore::new().with_rows(rows),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    )
}

async fn run(rig: &Rig) -> Result<(), BoxError> {
    rig.relay.run(&mut NullBatch).await
}

fn header<'a>(record: &'a PolicyLogRecord, name: &str) -> Option<&'a str> {
    record
        .headers
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn the_first_batch_takes_the_relay_over_and_publishes_every_row_in_order() {
    let rig = simple(vec![row(1), row(2)]);

    run(&rig).await.unwrap();

    let batches = rig.producer.batches();
    assert_eq!(batches.len(), 1);
    let keys: Vec<_> = batches[0]
        .iter()
        .map(|record| record.key.as_str())
        .collect();
    assert_eq!(keys, ["role/1", "role/2"]);
    assert_eq!(header(&batches[0][0], "iam-relay-epoch"), Some("1"));
    let published = rig.store.published();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0].0.offset, 0);
    assert_eq!(published[1].0.offset, 1);
    assert_eq!(published[0].1, RelayEpoch::new(1).unwrap());
    assert_eq!(rig.store.takeovers(), 1);
    assert_eq!(rig.store.unpublished(), 0);
}

#[tokio::test]
async fn a_leader_that_still_holds_the_latest_epoch_does_not_take_over_again() {
    let rig = simple(vec![row(1)]);

    run(&rig).await.unwrap();
    run(&rig).await.unwrap();

    assert_eq!(rig.store.takeovers(), 1);
    assert_eq!(rig.producer.batches().len(), 1);
}

#[tokio::test]
async fn a_replica_that_another_relay_replaced_takes_over_again() {
    let rig = simple(vec![]);
    run(&rig).await.unwrap();

    rig.store.another_relay_takes_over();
    run(&rig).await.unwrap();

    assert_eq!(rig.store.takeovers(), 2);
    assert_eq!(rig.store.epoch(), 3);
}

#[tokio::test]
async fn a_takeover_publishes_the_current_state_again_before_the_unpublished_rows() {
    let rig = rig(
        FakeOutboxStore::new()
            .with_rows(vec![row(3)])
            .with_republish(vec![row(1), row(2)]),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    );

    run(&rig).await.unwrap();

    let batches = rig.producer.batches();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(header(&batches[0][0], "iam-relay-epoch"), Some("1"));
    assert_eq!(batches[1][0].key, "role/3");
    assert_eq!(rig.store.published().len(), 3);
}

#[tokio::test]
async fn a_large_republication_is_sent_in_batches() {
    let settings = OutboxRelaySettings {
        batch_size: 2,
        ..OutboxRelaySettings::default()
    };
    let rig = rig(
        FakeOutboxStore::new().with_republish(vec![row(1), row(2), row(3)]),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        settings,
    );

    run(&rig).await.unwrap();

    let sizes: Vec<_> = rig.producer.batches().iter().map(Vec::len).collect();
    assert_eq!(sizes, [2, 1]);
}

#[tokio::test]
async fn a_batch_holds_at_most_the_batch_size() {
    let settings = OutboxRelaySettings {
        batch_size: 2,
        ..OutboxRelaySettings::default()
    };
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1), row(2), row(3)]),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        settings,
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.producer.batches()[0].len(), 2);
    assert_eq!(rig.store.unpublished(), 1);
}

#[tokio::test]
async fn a_misconfigured_topic_publishes_and_marks_nothing() {
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1)]),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::failing(vec![Violation::new("partitions", "1", "2")]),
        OutboxRelaySettings::default(),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.producer.batches().len(), 0);
    assert_eq!(rig.store.published().len(), 0);
    assert_eq!(rig.store.takeovers(), 0);
    assert_eq!(rig.store.unpublished(), 1);
}

#[tokio::test]
async fn an_unreachable_cluster_fails_the_batch() {
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1)]),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::unreachable(),
        OutboxRelaySettings::default(),
    );

    assert!(run(&rig).await.is_err());
    assert_eq!(rig.store.published().len(), 0);
}

#[tokio::test]
async fn the_verdict_is_trusted_for_its_time_to_live() {
    let rig = simple(vec![]);

    run(&rig).await.unwrap();
    rig.clock.advance(Duration::from_secs(4));
    run(&rig).await.unwrap();
    assert_eq!(rig.inspector.inspections(), 1);

    rig.clock.advance(Duration::from_secs(2));
    run(&rig).await.unwrap();
    assert_eq!(rig.inspector.inspections(), 2);
}

#[tokio::test]
async fn rows_stay_unpublished_while_the_broker_is_down_and_are_sent_again_afterwards() {
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1)]),
        FakePolicyLogProducer::new(&[Answer::Unavailable], Answer::Acknowledge),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    );

    assert!(run(&rig).await.is_err());
    assert_eq!(rig.store.published().len(), 0);
    assert_eq!(rig.store.unpublished(), 1);

    run(&rig).await.unwrap();

    assert_eq!(rig.store.unpublished(), 0);
    assert_eq!(rig.producer.batches().len(), 2);
}

#[tokio::test]
async fn a_fenced_producer_makes_the_next_batch_take_the_relay_over_again() {
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1)]),
        FakePolicyLogProducer::new(&[Answer::Fenced], Answer::Acknowledge),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    );

    assert!(run(&rig).await.is_err());
    run(&rig).await.unwrap();

    assert_eq!(rig.store.takeovers(), 2);
    assert_eq!(rig.store.unpublished(), 0);
}

#[tokio::test]
async fn an_incomplete_acknowledgement_marks_nothing() {
    let rig = rig(
        FakeOutboxStore::new().with_rows(vec![row(1), row(2)]),
        FakePolicyLogProducer::new(&[], Answer::Short),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    );

    let error = run(&rig).await.unwrap_err();

    assert_eq!(
        error.downcast_ref::<IncompleteAcknowledgement>(),
        Some(&IncompleteAcknowledgement {
            sent: 2,
            acknowledged: 1
        })
    );
    assert_eq!(rig.store.published().len(), 0);
}

#[tokio::test]
async fn a_failing_store_fails_the_batch() {
    for failing in [
        Failing::Claim,
        Failing::Epoch,
        Failing::Takeover,
        Failing::Mark,
    ] {
        let rig = rig(
            FakeOutboxStore::new()
                .with_rows(vec![row(1)])
                .failing(failing),
            FakePolicyLogProducer::acknowledging(),
            FakeTopicInspector::passing(),
            OutboxRelaySettings::default(),
        );

        assert!(run(&rig).await.is_err());
    }
}

#[tokio::test]
async fn a_failing_cleanup_fails_the_batch() {
    let rig = rig(
        FakeOutboxStore::new().failing(Failing::Delete),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        OutboxRelaySettings::default(),
    );

    assert!(run(&rig).await.is_err());
}

#[tokio::test]
async fn rows_published_more_than_a_week_ago_are_deleted_once_per_cleanup_period() {
    let rig = simple(vec![]);

    run(&rig).await.unwrap();
    run(&rig).await.unwrap();
    assert_eq!(
        rig.store.deleted_before(),
        [start() - Duration::from_hours(168)]
    );

    rig.clock.advance(Duration::from_secs(61));
    run(&rig).await.unwrap();

    assert_eq!(rig.store.deleted_before().len(), 2);
}

#[tokio::test]
async fn a_retention_beyond_what_the_clock_can_reach_back_deletes_nothing() {
    let rig = rig(
        FakeOutboxStore::new(),
        FakePolicyLogProducer::acknowledging(),
        FakeTopicInspector::passing(),
        OutboxRelaySettings {
            retention: Duration::MAX,
            ..OutboxRelaySettings::default()
        },
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.deleted_before().len(), 0);
}

#[tokio::test]
async fn the_listener_is_told_whether_this_replica_leads() {
    let rig = simple(vec![]);
    assert!(!*rig.leading.borrow());

    run(&rig).await.unwrap();
    assert!(*rig.leading.borrow());

    rig.relay.on_follower().await;
    assert!(!*rig.leading.borrow());
}

#[tokio::test]
async fn the_loop_polls_every_hundred_milliseconds_under_the_lock_of_the_relay() {
    let rig = simple(vec![row(1)]);
    let leadership = Arc::new(FakeSingletonLeadership::new(&[], Step::Lead));

    let singleton = rig.relay.into_loop(
        leadership,
        Arc::new(ManualClock::at(start())),
        Arc::new(Notify::new()),
    );
    let outcome = singleton.run_batch().await;

    assert_eq!(singleton.name(), "outbox-relay");
    assert_eq!(singleton.interval().get(), POLL_INTERVAL);
    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(rig.store.unpublished(), 0);
}

#[test]
fn the_incomplete_acknowledgement_names_both_counts() {
    let error = IncompleteAcknowledgement {
        sent: 3,
        acknowledged: 1,
    };

    assert_eq!(
        error.to_string(),
        "the producer acknowledged 1 of 3 records"
    );
}
