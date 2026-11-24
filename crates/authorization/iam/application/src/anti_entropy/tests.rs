use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    LeaderBatch, PolicyDigestValue, PolicyVersion, PublishedRecord, RepositoryError, TaskState,
    TopicAheadState, WrittenKey,
};
use shared_domain::Uuid;
use test_support::anti_entropy::{
    FakeAntiEntropyStore, FakePolicyLogTail, HashDigest, TextHeadCodec, head_record, tail_record,
};
use test_support::clock::ManualClock;
use test_support::singleton_leadership::FakeSingletonLeadership;
use test_support::task_state::FakeTaskStateRepository;

use super::{
    AntiEntropyChecker, AntiEntropyCounters, AntiEntropyPorts, AntiEntropySettings, TopicAheadHold,
};
use crate::singleton_loop::SingletonWork as _;

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const OTHER: &str = "role/0192f6a0-0000-7000-8000-000000000002";

#[derive(Debug, Default)]
struct NullBatch {
    written: Option<bool>,
}

#[async_trait::async_trait]
impl LeaderBatch for NullBatch {
    async fn record_run(&mut self, _at: SystemTime) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn write_topic_ahead(
        &mut self,
        held: bool,
        _at: SystemTime,
    ) -> Result<(), RepositoryError> {
        self.written = Some(held);
        Ok(())
    }

    async fn read_topic_ahead(
        &mut self,
        _checker: &str,
    ) -> Result<TopicAheadState, RepositoryError> {
        Ok(TopicAheadState::default())
    }

    async fn commit(self: Box<Self>) -> Result<(), RepositoryError> {
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RepositoryError> {
        Ok(())
    }
}

struct Rig {
    checker: AntiEntropyChecker,
    clock: Arc<ManualClock>,
    counters: Arc<AntiEntropyCounters>,
    hold: Arc<TopicAheadHold>,
    store: Arc<FakeAntiEntropyStore>,
    tail: Arc<FakePolicyLogTail>,
}

fn start() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn uuid(last: u8) -> Uuid {
    Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-0000000000{last:02x}")).unwrap()
}

fn version(number: i64) -> PolicyVersion {
    PolicyVersion::new(number).unwrap()
}

fn digest_of(entities: &[(&str, &str)]) -> PolicyDigestValue {
    entities
        .iter()
        .map(|(key, canonical)| HashDigest::of(key, canonical))
        .fold(PolicyDigestValue::ZERO, PolicyDigestValue::combined)
}

fn published(id: u8, key: &str, number: i64, offset: i64) -> PublishedRecord {
    PublishedRecord {
        id: uuid(id),
        key: key.to_owned(),
        version: version(number),
        offset,
    }
}

fn written(id: u8, key: &str, number: i64, offset: Option<i64>) -> WrittenKey {
    WrittenKey {
        id: uuid(id),
        key: key.to_owned(),
        version: version(number),
        published_offset: offset,
    }
}

fn rig(store: FakeAntiEntropyStore, tail: FakePolicyLogTail) -> Rig {
    rig_with(store, tail, FakeTaskStateRepository::new())
}

fn rig_with(
    store: FakeAntiEntropyStore,
    tail: FakePolicyLogTail,
    task_states: FakeTaskStateRepository,
) -> Rig {
    let clock = Arc::new(ManualClock::at(start()));
    let counters = Arc::new(AntiEntropyCounters::new());
    let hold = Arc::new(TopicAheadHold::new());
    let store = Arc::new(store);
    let tail = Arc::new(tail);
    let ports = AntiEntropyPorts {
        store: Arc::<FakeAntiEntropyStore>::clone(&store),
        tail: Arc::<FakePolicyLogTail>::clone(&tail),
        task_states: Arc::new(task_states),
        codec: Arc::new(TextHeadCodec),
        digest: Arc::new(HashDigest),
    };
    let checker = AntiEntropyChecker::new(
        ports,
        Arc::<ManualClock>::clone(&clock),
        AntiEntropySettings::default(),
        Arc::clone(&counters),
        Arc::clone(&hold),
    );
    Rig {
        checker,
        clock,
        counters,
        hold,
        store,
        tail,
    }
}

/// A topic and a store in step at version 1: one role.
fn in_step() -> Rig {
    in_step_over(|tail| tail)
}

/// [`in_step`] over the topic that `topic` makes of its records.
fn in_step_over(topic: impl FnOnce(FakePolicyLogTail) -> FakePolicyLogTail) -> Rig {
    let digest = digest_of(&[(ROLE, "a")]);
    rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, ROLE, 1, 0), published(2, "__head", 1, 1)])
            .with_written(
                vec![
                    written(1, ROLE, 1, Some(0)),
                    written(2, "__head", 1, Some(1)),
                ],
                true,
            ),
        topic(FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ])),
    )
}

async fn run(rig: &Rig) -> Result<(), shared_domain::BoxError> {
    rig.checker.run(&mut NullBatch::default()).await
}

/// The hold that the batch of one check wrote to the shared state.
async fn written_hold(rig: &Rig) -> Option<bool> {
    let mut batch = NullBatch::default();
    rig.checker.run(&mut batch).await.unwrap();
    batch.written
}

#[tokio::test]
async fn a_topic_in_step_with_postgresql_repairs_nothing_and_is_healthy() {
    let rig = in_step();

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished().len(), 0);
    assert_eq!(rig.counters.repairs_total(), 0);
    assert!(rig.checker.is_healthy());
    assert!(!rig.hold.is_set());
}

#[tokio::test]
async fn a_recent_record_missing_at_its_offset_is_published_again() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest).with_published(vec![published(1, OTHER, 1, 0)]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_recent_record_with_another_version_at_its_offset_is_published_again() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest).with_published(vec![published(1, ROLE, 2, 0)]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
}

#[tokio::test]
async fn a_lost_superseded_recent_row_is_not_published_again_when_the_newest_row_holds() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, OTHER, 1, 0)])
            .with_newest(vec![written(2, OTHER, 2, Some(1))]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            tail_record(1, OTHER, Some("b"), 2, 1),
            head_record(2, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), Vec::<Uuid>::new());
}

#[tokio::test]
async fn a_lost_superseded_recent_row_repairs_the_newest_row_of_its_key_when_that_is_lost() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, OTHER, 1, 0)])
            .with_newest(vec![written(2, OTHER, 2, Some(1))]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            tail_record(1, ROLE, Some("a"), 1, 1),
            head_record(2, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(2)]);
}

#[tokio::test]
async fn a_lost_superseded_recent_row_leaves_an_unpublished_newest_row_to_the_relay() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, OTHER, 1, 0)])
            .with_newest(vec![written(2, OTHER, 2, None)]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), Vec::<Uuid>::new());
}

#[tokio::test]
async fn a_lost_recent_row_that_is_the_newest_of_its_key_is_published_again() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, OTHER, 1, 0)])
            .with_newest(vec![written(1, OTHER, 1, Some(0))]),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
}

#[tokio::test]
async fn a_key_whose_last_record_is_lower_than_postgresql_is_published_again() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest)
            .with_unpublished(1)
            .with_written(vec![written(1, ROLE, 2, Some(0))], true),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_zombie_record_appended_after_the_takeover_republish_is_repaired() {
    let digest = digest_of(&[(ROLE, "b")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest).with_written(vec![written(1, ROLE, 2, Some(0))], true),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("b"), 2, 2),
            tail_record(1, ROLE, Some("a"), 1, 1),
            head_record(2, 2, digest, 2),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
}

#[tokio::test]
async fn a_key_without_a_record_on_the_topic_is_published_again() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO)
            .with_written(vec![written(1, ROLE, 1, Some(0))], true),
        FakePolicyLogTail::with(vec![head_record(1, 1, PolicyDigestValue::ZERO, 1)]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
}

#[tokio::test]
async fn a_row_that_is_both_recent_and_written_is_repaired_once() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest)
            .with_unpublished(1)
            .with_published(vec![published(1, ROLE, 2, 0)])
            .with_written(vec![written(1, ROLE, 2, Some(0))], false),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished(), vec![uuid(1)]);
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_key_that_is_not_published_yet_is_left_to_the_relay() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest)
            .with_unpublished(1)
            .with_written(vec![written(1, ROLE, 2, None)], true),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished().len(), 0);
    assert_eq!(rig.counters.repairs_total(), 0);
}

#[tokio::test]
async fn a_lost_record_whose_row_is_gone_is_an_alert() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_written(vec![written(9, OTHER, 1, Some(0))], false),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished().len(), 0);
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_topic_ahead_of_postgresql_sets_the_hold_and_raises_the_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(3, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![head_record(0, 5, PolicyDigestValue::ZERO, 1)]),
    );

    run(&rig).await.unwrap();

    assert!(rig.hold.is_set());
    assert_eq!(rig.counters.repairs_total(), 1);
    assert_eq!(rig.store.republished().len(), 0);
}

#[tokio::test]
async fn the_hold_is_released_when_the_topic_is_no_longer_ahead() {
    let rig = in_step();
    rig.hold.set(true);

    run(&rig).await.unwrap();

    assert!(!rig.hold.is_set());
}

#[tokio::test]
async fn the_newest_head_is_found_behind_several_windows() {
    let digest = digest_of(&[(ROLE, "a")]);
    let mut records = vec![head_record(0, 1, digest, 1)];
    records.extend((1..1_100).map(|offset| tail_record(offset, OTHER, Some("x"), 1, 1)));
    let rig = rig(
        FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(records),
    );

    run(&rig).await.unwrap();

    assert!(rig.hold.is_set());
}

#[tokio::test]
async fn a_head_that_cannot_be_read_is_an_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![tail_record(0, "__head", Some("garbage"), 1, 1)]),
    );

    run(&rig).await.unwrap();

    assert!(rig.counters.repairs_total() >= 1);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_corrupted_value_is_a_digest_mismatch_and_nothing_is_healthy() {
    let expected = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, expected),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("corrupted"), 1, 1),
            head_record(1, 1, expected, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 1);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_topic_digest_that_differs_from_postgresql_at_the_same_version_is_an_alert() {
    let topic = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest_of(&[(ROLE, "other")])),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, topic, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 1);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_consistent_topic_ahead_in_the_full_check_is_an_alert() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert!(rig.hold.is_set());
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_topic_behind_with_rows_waiting_is_neither_an_alert_nor_healthy() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest_of(&[(ROLE, "b")])).with_unpublished(1),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 0);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_topic_behind_with_nothing_left_to_publish_is_an_alert() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest_of(&[(ROLE, "b")])),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn an_incomplete_version_is_waited_for() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(2, digest).with_unpublished(1),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
            tail_record(2, OTHER, Some("b"), 2, 1),
        ]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 0);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn an_empty_topic_and_an_empty_policy_are_in_step() {
    let rig = rig(
        FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()),
    );

    run(&rig).await.unwrap();

    assert!(rig.checker.is_healthy());
}

#[tokio::test]
async fn an_empty_topic_under_a_policy_with_nothing_to_publish_is_an_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest_of(&[(ROLE, "a")])),
        FakePolicyLogTail::with(Vec::new()),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_record_that_cannot_be_applied_is_an_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![tail_record(0, "not-a-key", Some("a"), 1, 1)]),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.counters.repairs_total(), 1);
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn the_full_check_runs_once_per_full_interval() {
    let rig = in_step();
    run(&rig).await.unwrap();
    assert!(rig.checker.is_healthy());
    rig.tail
        .append(tail_record(2, ROLE, Some("corrupted"), 1, 1));

    run(&rig).await.unwrap();
    assert!(rig.checker.is_healthy());

    rig.clock.advance(Duration::from_mins(11));
    run(&rig).await.unwrap();
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn a_malformed_record_is_an_alert_and_fails_the_batch() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, PolicyDigestValue::ZERO, 1),
        ])
        .malformed_at(0),
    );

    let failed = run(&rig).await;

    assert!(failed.is_err());
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn an_unavailable_topic_fails_the_batch_without_an_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()).unavailable(),
    );

    assert!(run(&rig).await.is_err());
    assert_eq!(rig.counters.repairs_total(), 0);
}

#[tokio::test]
async fn an_unavailable_store_fails_the_batch() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO).unavailable(),
        FakePolicyLogTail::with(Vec::new()),
    );

    assert!(run(&rig).await.is_err());
}

#[tokio::test]
async fn the_written_keys_are_read_from_the_previous_check_with_an_overlap() {
    let last_run_at = start().checked_sub(Duration::from_secs(5)).unwrap();
    let states = FakeTaskStateRepository::new().with_state(
        AntiEntropyChecker::TASK.name(),
        TaskState {
            last_run_at,
            run_count: 3,
        },
    );
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig_with(
        FakeAntiEntropyStore::at(1, digest),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ]),
        states,
    );

    run(&rig).await.unwrap();

    assert!(rig.checker.is_healthy());
}

#[tokio::test]
async fn a_failing_task_state_fails_the_batch() {
    let rig = rig_with(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()),
        FakeTaskStateRepository::failing(),
    );

    assert!(run(&rig).await.is_err());
    assert!(rig.checker.is_due(start()).await.is_err());
}

#[tokio::test]
async fn a_check_is_due_when_none_ran_or_the_head_interval_passed() {
    let store = || FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO);
    let never = rig(store(), FakePolicyLogTail::with(Vec::new()));
    assert!(never.checker.is_due(start()).await.unwrap());

    let last_run_at = start();
    let states = |last_run_at| {
        FakeTaskStateRepository::new().with_state(
            AntiEntropyChecker::TASK.name(),
            TaskState {
                last_run_at,
                run_count: 1,
            },
        )
    };
    let ran = rig_with(
        store(),
        FakePolicyLogTail::with(Vec::new()),
        states(last_run_at),
    );
    let soon = start().checked_add(Duration::from_secs(4)).unwrap();
    let later = start().checked_add(Duration::from_secs(5)).unwrap();
    let before = start().checked_sub(Duration::from_secs(1)).unwrap();

    assert!(!ran.checker.is_due(soon).await.unwrap());
    assert!(ran.checker.is_due(later).await.unwrap());
    assert!(!ran.checker.is_due(before).await.unwrap());
}

#[tokio::test]
async fn the_loop_polls_at_the_head_interval_but_at_most_every_ten_seconds() {
    let short = rig(
        FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()),
    );
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let clock = Arc::new(ManualClock::at(start()));

    let singleton = short.checker.into_loop(
        Arc::<FakeSingletonLeadership>::clone(&leadership),
        Arc::<ManualClock>::clone(&clock),
    );
    assert_eq!(singleton.interval().get(), Duration::from_secs(5));
    assert_eq!(singleton.name(), "anti-entropy");

    let long = AntiEntropyChecker::new(
        AntiEntropyPorts {
            store: Arc::new(FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO)),
            tail: Arc::new(FakePolicyLogTail::with(Vec::new())),
            task_states: Arc::new(FakeTaskStateRepository::new()),
            codec: Arc::new(TextHeadCodec),
            digest: Arc::new(HashDigest),
        },
        Arc::<ManualClock>::clone(&clock),
        AntiEntropySettings::new(Duration::from_mins(1), Duration::from_mins(2)).unwrap(),
        Arc::new(AntiEntropyCounters::new()),
        Arc::new(TopicAheadHold::new()),
    );
    let singleton = long.into_loop(leadership, clock);
    assert_eq!(singleton.interval().get(), Duration::from_secs(10));
}

#[tokio::test]
async fn the_reader_of_the_topic_is_closed_when_the_task_stops_or_another_replica_leads() {
    let rig = in_step();

    rig.checker.on_stop().await;
    assert_eq!(rig.tail.closes(), 1);

    rig.checker.on_follower().await;
    assert_eq!(rig.tail.closes(), 2);
}

#[test]
fn a_check_in_flight_may_be_abandoned_when_the_service_stops() {
    assert!(in_step().checker.interruptible());
}

#[tokio::test]
async fn a_watermark_past_the_last_record_ends_every_read_at_the_last_record() {
    let digest = digest_of(&[(ROLE, "a")]);
    let rig = rig(
        FakeAntiEntropyStore::at(1, digest)
            .with_published(vec![published(1, ROLE, 1, 0), published(2, "__head", 1, 1)])
            .with_written(
                vec![
                    written(1, ROLE, 1, Some(0)),
                    written(2, "__head", 1, Some(1)),
                ],
                true,
            ),
        FakePolicyLogTail::with(vec![
            tail_record(0, ROLE, Some("a"), 1, 1),
            head_record(1, 1, digest, 1),
        ])
        .with_watermark(3),
    );

    run(&rig).await.unwrap();

    assert_eq!(rig.store.republished().len(), 0);
    assert_eq!(rig.counters.repairs_total(), 0);
    assert!(rig.checker.is_healthy());
}

#[tokio::test]
async fn a_full_check_that_finds_the_topic_ahead_first_sets_the_hold_and_raises_the_alert() {
    let rig = rig(
        FakeAntiEntropyStore::at(3, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![head_record(0, 5, PolicyDigestValue::ZERO, 1)]),
    );

    super::full::FullCheck(&rig.checker)
        .check_full()
        .await
        .unwrap();

    assert!(rig.hold.is_set());
    assert_eq!(rig.counters.repairs_total(), 1);
}

#[tokio::test]
async fn a_full_check_whose_topic_cannot_be_read_fails_the_batch() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()).unavailable(),
    );

    let checked = super::full::FullCheck(&rig.checker).check_full().await;

    assert!(checked.is_err());
    assert!(!rig.checker.is_healthy());
}

#[tokio::test]
async fn an_offset_that_cannot_be_read_back_fails_the_batch_without_a_repair() {
    let rig = in_step_over(FakePolicyLogTail::unreadable_offsets);

    assert!(run(&rig).await.is_err());
    assert_eq!(rig.store.republished().len(), 0);
}

#[tokio::test]
async fn a_watermark_lost_between_the_checks_fails_the_batch_without_a_repair() {
    let rig = in_step_over(|tail| tail.watermark_fails_after(1));

    assert!(run(&rig).await.is_err());
    assert_eq!(rig.store.republished().len(), 0);
}

#[tokio::test]
async fn a_check_writes_a_topic_that_is_ahead_to_the_shared_state() {
    let rig = rig(
        FakeAntiEntropyStore::at(3, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(vec![head_record(0, 5, PolicyDigestValue::ZERO, 1)]),
    );

    assert_eq!(written_hold(&rig).await, Some(true));
}

#[tokio::test]
async fn a_check_that_finds_the_topic_in_step_writes_the_hold_released() {
    let rig = in_step();
    rig.hold.set(true);

    assert_eq!(written_hold(&rig).await, Some(false));
}

#[tokio::test]
async fn a_check_that_fails_writes_no_hold() {
    let rig = rig(
        FakeAntiEntropyStore::at(1, PolicyDigestValue::ZERO),
        FakePolicyLogTail::with(Vec::new()).unavailable(),
    );
    let mut batch = NullBatch::default();

    let outcome = rig.checker.run(&mut batch).await;

    assert!(outcome.is_err());
    assert_eq!(batch.written, None);
}
