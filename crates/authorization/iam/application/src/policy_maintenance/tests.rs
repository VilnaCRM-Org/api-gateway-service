use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    EntityVersion, ExpiredOrphanedGrant, PermissionGrant, PermissionGrantSet, RoleId, RoleKind,
    RoleName, RoleParts, SingletonLeadership, TaskState,
};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::maintenance_store::{Failing, FakeMaintenanceStore};
use test_support::role::FakeRoleRepository;
use test_support::singleton_leadership::{Event, FakeSingletonLeadership, Step};
use test_support::task_state::FakeTaskStateRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{MaintenanceSettings, PolicyMaintenance};
use crate::command::run_maintenance::RunMaintenanceCommandHandler;
use crate::singleton_loop::{BatchOutcome, MAX_SINGLETON_INTERVAL};

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const ORPHANED: &str = "rest:billing:GET /invoices";
const INTERVAL: Duration = Duration::from_mins(10);
const RETENTION: Duration = Duration::from_hours(2_160);

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn settings(interval: Duration) -> MaintenanceSettings {
    MaintenanceSettings {
        interval,
        orphaned_grant_retention: RETENTION,
    }
}

fn state_before_now(elapsed: Duration) -> TaskState {
    TaskState {
        last_run_at: at().checked_sub(elapsed).unwrap(),
        run_count: 1,
    }
}

fn maintenance(
    store: &Arc<FakeMaintenanceStore>,
    task_states: FakeTaskStateRepository,
    interval: Duration,
) -> PolicyMaintenance {
    let role = RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new([PermissionGrant::parse(ORPHANED).unwrap()]).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    };
    let handler = RunMaintenanceCommandHandler::new(
        Arc::<FakeMaintenanceStore>::clone(store),
        Arc::new(FakeRoleRepository::holding(vec![role])),
        Arc::new(FakeIamUnitOfWork::new()),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    PolicyMaintenance::new(handler, Arc::new(task_states), settings(interval))
}

fn orphan() -> ExpiredOrphanedGrant {
    ExpiredOrphanedGrant {
        role_id: RoleId::parse(ROLE).unwrap(),
        grant: PermissionGrant::parse(ORPHANED).unwrap(),
        orphaned_at: SystemTime::UNIX_EPOCH,
    }
}

/// The outcome and the events of one batch of the task on a replica that leads it.
async fn batch(
    store: &Arc<FakeMaintenanceStore>,
    task_states: FakeTaskStateRepository,
) -> (BatchOutcome, Vec<Event>) {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let singleton = maintenance(store, task_states, INTERVAL)
        .into_loop(
            Arc::<FakeSingletonLeadership>::clone(&leadership),
            Arc::new(FixedClock::at(at())),
        )
        .unwrap();
    let outcome = singleton.run_batch().await;
    (outcome, leadership.events())
}

#[test]
fn the_default_settings_are_ten_minutes_and_ninety_days() {
    let settings = MaintenanceSettings::default();

    assert_eq!(settings.interval, Duration::from_mins(10));
    assert_eq!(
        settings.orphaned_grant_retention,
        Duration::from_hours(2_160)
    );
}

#[test]
fn the_task_is_named_and_has_its_own_lock_constant() {
    assert_eq!(PolicyMaintenance::TASK.name(), "policy-maintenance");
    assert_eq!(PolicyMaintenance::TASK.lock_key(), 7_008);
}

#[test]
fn the_loop_polls_at_the_longest_retry_interval_for_a_longer_period() {
    let store = Arc::new(FakeMaintenanceStore::new());

    let singleton = maintenance(&store, FakeTaskStateRepository::new(), INTERVAL)
        .into_loop(
            Arc::new(FakeSingletonLeadership::leading()),
            Arc::new(FixedClock::at(at())),
        )
        .unwrap();

    assert_eq!(singleton.name(), "policy-maintenance");
    assert_eq!(singleton.interval().get(), MAX_SINGLETON_INTERVAL);
}

#[test]
fn the_loop_polls_at_a_period_shorter_than_the_retry_interval() {
    let store = Arc::new(FakeMaintenanceStore::new());
    let period = Duration::from_secs(3);

    let singleton = maintenance(&store, FakeTaskStateRepository::new(), period)
        .into_loop(
            Arc::new(FakeSingletonLeadership::leading()),
            Arc::new(FixedClock::at(at())),
        )
        .unwrap();

    assert_eq!(singleton.interval().get(), period);
}

#[test]
fn a_zero_maintenance_interval_cannot_make_a_loop() {
    let store = Arc::new(FakeMaintenanceStore::new());

    let refused = maintenance(&store, FakeTaskStateRepository::new(), Duration::ZERO).into_loop(
        Arc::new(FakeSingletonLeadership::leading()),
        Arc::new(FixedClock::at(at())),
    );

    assert!(refused.is_err());
}

#[tokio::test]
async fn the_first_batch_of_a_task_that_never_ran_runs_a_pass_and_records_it() {
    let store = Arc::new(FakeMaintenanceStore::new().with_orphans(vec![orphan()]));

    let (outcome, events) = batch(&store, FakeTaskStateRepository::new()).await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(store.anchors().len(), 1);
    assert_eq!(
        events,
        [
            Event::Begun("policy-maintenance".to_owned()),
            Event::Recorded(at()),
            Event::Committed,
        ]
    );
}

#[tokio::test]
async fn a_batch_after_the_interval_runs_a_pass() {
    let store = Arc::new(FakeMaintenanceStore::new());
    let states =
        FakeTaskStateRepository::new().with_state("policy-maintenance", state_before_now(INTERVAL));

    let (outcome, _events) = batch(&store, states).await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(store.anchors().len(), 1);
}

#[tokio::test]
async fn a_batch_within_the_interval_runs_nothing_and_records_nothing() {
    let store = Arc::new(FakeMaintenanceStore::new());
    let states = FakeTaskStateRepository::new().with_state(
        "policy-maintenance",
        state_before_now(INTERVAL.checked_sub(Duration::from_secs(1)).unwrap()),
    );

    let (outcome, events) = batch(&store, states).await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(store.anchors().len(), 0);
    assert_eq!(
        events,
        [
            Event::Begun("policy-maintenance".to_owned()),
            Event::RolledBack
        ]
    );
}

#[tokio::test]
async fn a_last_run_in_the_future_is_not_due() {
    let store = Arc::new(FakeMaintenanceStore::new());
    let states = FakeTaskStateRepository::new().with_state(
        "policy-maintenance",
        TaskState {
            last_run_at: at().checked_add(Duration::from_secs(5)).unwrap(),
            run_count: 1,
        },
    );

    let (outcome, _events) = batch(&store, states).await;

    assert_eq!(outcome, BatchOutcome::Skipped);
}

#[tokio::test]
async fn a_task_state_that_cannot_be_read_rolls_the_batch_back() {
    let store = Arc::new(FakeMaintenanceStore::new());

    let (outcome, _events) = batch(&store, FakeTaskStateRepository::failing()).await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(store.anchors().len(), 0);
}

#[tokio::test]
async fn a_failing_pass_rolls_the_batch_back_without_recording_a_run() {
    let store = Arc::new(FakeMaintenanceStore::new().failing(Failing::Anchor));

    let (outcome, events) = batch(&store, FakeTaskStateRepository::new()).await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(
        events,
        [
            Event::Begun("policy-maintenance".to_owned()),
            Event::RolledBack
        ]
    );
}

#[tokio::test]
async fn a_replica_without_the_lock_skips_the_batch() {
    let store = Arc::new(FakeMaintenanceStore::new());
    let leadership: Arc<dyn SingletonLeadership> =
        Arc::new(FakeSingletonLeadership::new(&[], Step::Follow));
    let singleton = maintenance(&store, FakeTaskStateRepository::new(), INTERVAL)
        .into_loop(leadership, Arc::new(FixedClock::at(at())))
        .unwrap();

    let outcome = singleton.run_batch().await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(store.anchors().len(), 0);
}
