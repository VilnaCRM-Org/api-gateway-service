use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{ExpiredRevocation, SessionId, SingletonLeadership, TaskState};
use test_support::clock::FixedClock;
use test_support::expired_revocation_store::FakeExpiredRevocationStore;
use test_support::id::SequenceUuidGenerator;
use test_support::singleton_leadership::{Event, FakeSingletonLeadership, Step};
use test_support::task_state::FakeTaskStateRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::RevocationTombstoneEmitter;
use crate::command::emit_revocation_tombstones::EmitRevocationTombstonesCommandHandler;
use crate::singleton_loop::{BatchOutcome, MAX_SINGLETON_INTERVAL};

const INTERVAL: Duration = Duration::from_mins(10);
const NAME: &str = "revocation-tombstone-emitter";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn state_before_now(elapsed: Duration) -> TaskState {
    TaskState {
        last_run_at: at().checked_sub(elapsed).unwrap(),
        run_count: 1,
    }
}

fn expired() -> ExpiredRevocation {
    ExpiredRevocation::Session {
        session: SessionId::new("sid-1").unwrap(),
        prune_after: SystemTime::UNIX_EPOCH,
    }
}

fn emitter(
    unit_of_work: &Arc<FakeIamUnitOfWork>,
    store: FakeExpiredRevocationStore,
    task_states: FakeTaskStateRepository,
    interval: Duration,
) -> RevocationTombstoneEmitter {
    let handler = EmitRevocationTombstonesCommandHandler::new(
        Arc::new(store),
        Arc::<FakeIamUnitOfWork>::clone(unit_of_work),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    RevocationTombstoneEmitter::new(handler, Arc::new(task_states), interval)
}

async fn batch(
    unit_of_work: &Arc<FakeIamUnitOfWork>,
    store: FakeExpiredRevocationStore,
    task_states: FakeTaskStateRepository,
) -> (BatchOutcome, Vec<Event>) {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let singleton = emitter(unit_of_work, store, task_states, INTERVAL)
        .into_loop(
            Arc::<FakeSingletonLeadership>::clone(&leadership),
            Arc::new(FixedClock::at(at())),
        )
        .unwrap();
    let outcome = singleton.run_batch().await;
    (outcome, leadership.events())
}

#[test]
fn the_task_is_named_and_has_its_own_lock_constant() {
    assert_eq!(RevocationTombstoneEmitter::TASK.name(), NAME);
    assert_eq!(RevocationTombstoneEmitter::TASK.lock_key(), 7_010);
}

#[test]
fn the_loop_polls_at_the_longest_retry_interval_for_a_longer_period() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let singleton = emitter(
        &unit_of_work,
        FakeExpiredRevocationStore::new(),
        FakeTaskStateRepository::new(),
        INTERVAL,
    )
    .into_loop(
        Arc::new(FakeSingletonLeadership::leading()),
        Arc::new(FixedClock::at(at())),
    )
    .unwrap();

    assert_eq!(singleton.name(), NAME);
    assert_eq!(singleton.interval().get(), MAX_SINGLETON_INTERVAL);
}

#[test]
fn a_zero_interval_cannot_make_a_loop() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let refused = emitter(
        &unit_of_work,
        FakeExpiredRevocationStore::new(),
        FakeTaskStateRepository::new(),
        Duration::ZERO,
    )
    .into_loop(
        Arc::new(FakeSingletonLeadership::leading()),
        Arc::new(FixedClock::at(at())),
    );

    assert!(refused.is_err());
}

#[tokio::test]
async fn the_first_batch_commits_the_tombstones_and_records_the_run() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let store = FakeExpiredRevocationStore::new().holding(vec![expired()]);

    let (outcome, events) = batch(&unit_of_work, store, FakeTaskStateRepository::new()).await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(unit_of_work.committed().len(), 1);
    assert_eq!(
        events,
        [
            Event::Begun(NAME.to_owned()),
            Event::Recorded(at()),
            Event::Committed,
        ]
    );
}

#[tokio::test]
async fn a_batch_after_the_interval_runs() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let store = FakeExpiredRevocationStore::new().holding(vec![expired()]);
    let states = FakeTaskStateRepository::new().with_state(NAME, state_before_now(INTERVAL));

    let (outcome, _events) = batch(&unit_of_work, store, states).await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_batch_within_the_interval_runs_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let store = FakeExpiredRevocationStore::new().holding(vec![expired()]);
    let states = FakeTaskStateRepository::new().with_state(
        NAME,
        state_before_now(INTERVAL.checked_sub(Duration::from_secs(1)).unwrap()),
    );

    let (outcome, events) = batch(&unit_of_work, store, states).await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(unit_of_work.committed().len(), 0);
    assert_eq!(events, [Event::Begun(NAME.to_owned()), Event::RolledBack]);
}

#[tokio::test]
async fn a_last_run_in_the_future_is_not_due() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let states = FakeTaskStateRepository::new().with_state(
        NAME,
        TaskState {
            last_run_at: at().checked_add(Duration::from_secs(5)).unwrap(),
            run_count: 1,
        },
    );

    let (outcome, _events) = batch(&unit_of_work, FakeExpiredRevocationStore::new(), states).await;

    assert_eq!(outcome, BatchOutcome::Skipped);
}

#[tokio::test]
async fn a_task_state_that_cannot_be_read_rolls_the_batch_back() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let (outcome, _events) = batch(
        &unit_of_work,
        FakeExpiredRevocationStore::new(),
        FakeTaskStateRepository::failing(),
    )
    .await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
}

#[tokio::test]
async fn a_failing_run_rolls_the_batch_back_without_recording_a_run() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let (outcome, events) = batch(
        &unit_of_work,
        FakeExpiredRevocationStore::failing(),
        FakeTaskStateRepository::new(),
    )
    .await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(events, [Event::Begun(NAME.to_owned()), Event::RolledBack]);
}

#[tokio::test]
async fn a_replica_without_the_lock_skips_the_batch() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let store = FakeExpiredRevocationStore::new().holding(vec![expired()]);
    let leadership: Arc<dyn SingletonLeadership> =
        Arc::new(FakeSingletonLeadership::new(&[], Step::Follow));
    let singleton = emitter(
        &unit_of_work,
        store,
        FakeTaskStateRepository::new(),
        INTERVAL,
    )
    .into_loop(leadership, Arc::new(FixedClock::at(at())))
    .unwrap();

    let outcome = singleton.run_batch().await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(unit_of_work.committed().len(), 0);
}
