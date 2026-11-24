use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{LeaderBatch, SingletonLeadership, SingletonTask};
use shared_domain::BoxError;
use test_support::clock::FixedClock;
use test_support::singleton_leadership::{Event, FakeSingletonLeadership, Step};
use tokio::sync::{Notify, watch};

use super::{
    BatchOutcome, InvalidSingletonInterval, MAX_SINGLETON_INTERVAL, SingletonInterval,
    SingletonLoop, SingletonWork,
};

const TASK: SingletonTask = SingletonTask::new("test-task", 42);
const INTERVAL: Duration = Duration::from_secs(2);

/// Work that counts its batches and fails when told to.
#[derive(Debug, Default)]
struct CountingWork {
    runs: AtomicUsize,
    fail: bool,
}

#[async_trait::async_trait]
impl SingletonWork for CountingWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("the work failed".into());
        }
        Ok(())
    }
}

/// What the due check of [`ScheduledWork`] answers.
#[derive(Debug, Clone, Copy)]
enum Due {
    Yes,
    No,
    Fails,
}

/// Work that counts its batches and answers the due check as told.
#[derive(Debug)]
struct ScheduledWork {
    due: Due,
    runs: AtomicUsize,
}

#[async_trait::async_trait]
impl SingletonWork for ScheduledWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn is_due(&self, _now: SystemTime) -> Result<bool, BoxError> {
        match self.due {
            Due::Yes => Ok(true),
            Due::No => Ok(false),
            Due::Fails => Err("the due check failed".into()),
        }
    }
}

async fn scheduled(due: Due) -> (BatchOutcome, usize, Vec<Event>) {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(ScheduledWork {
        due,
        runs: AtomicUsize::new(0),
    });
    let singleton = SingletonLoop::new(
        TASK,
        interval(),
        Arc::<FakeSingletonLeadership>::clone(&leadership),
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        Arc::<ScheduledWork>::clone(&work),
    );

    let outcome = singleton.run_batch().await;

    (
        outcome,
        work.runs.load(Ordering::SeqCst),
        leadership.events(),
    )
}

#[tokio::test]
async fn work_that_is_due_runs_and_records_its_run() {
    let (outcome, runs, events) = scheduled(Due::Yes).await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(runs, 1);
    assert_eq!(
        events,
        [
            Event::Begun("test-task".to_owned()),
            Event::Recorded(UNIX_EPOCH),
            Event::Committed,
        ]
    );
}

#[tokio::test]
async fn work_that_is_not_due_is_skipped_without_a_record_of_a_run() {
    let (outcome, runs, events) = scheduled(Due::No).await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(runs, 0);
    assert_eq!(
        events,
        [Event::Begun("test-task".to_owned()), Event::RolledBack]
    );
}

#[tokio::test]
async fn a_failing_due_check_rolls_the_batch_back_without_running_the_work() {
    let (outcome, runs, events) = scheduled(Due::Fails).await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(runs, 0);
    assert_eq!(
        events,
        [Event::Begun("test-task".to_owned()), Event::RolledBack]
    );
}

fn interval() -> SingletonInterval {
    SingletonInterval::new(INTERVAL).unwrap()
}

fn singleton(leadership: &Arc<FakeSingletonLeadership>, work: &Arc<CountingWork>) -> SingletonLoop {
    let leadership: Arc<dyn SingletonLeadership> =
        Arc::<FakeSingletonLeadership>::clone(leadership);
    let work: Arc<dyn SingletonWork> = Arc::<CountingWork>::clone(work);
    SingletonLoop::new(
        TASK,
        interval(),
        leadership,
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        work,
    )
}

#[test]
fn an_interval_between_zero_and_ten_seconds_is_accepted() {
    assert_eq!(
        SingletonInterval::new(MAX_SINGLETON_INTERVAL)
            .unwrap()
            .get(),
        MAX_SINGLETON_INTERVAL
    );
    assert_eq!(
        SingletonInterval::new(Duration::from_millis(1))
            .unwrap()
            .get(),
        Duration::from_millis(1)
    );
}

#[test]
fn a_zero_interval_or_one_above_ten_seconds_is_refused() {
    let too_long = MAX_SINGLETON_INTERVAL + Duration::from_nanos(1);

    assert_eq!(
        SingletonInterval::new(Duration::ZERO),
        Err(InvalidSingletonInterval {
            requested: Duration::ZERO
        })
    );
    assert_eq!(
        SingletonInterval::new(too_long),
        Err(InvalidSingletonInterval {
            requested: too_long
        })
    );
}

#[tokio::test]
async fn a_led_batch_runs_the_work_records_the_run_and_commits() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::Committed);
    assert_eq!(work.runs.load(Ordering::SeqCst), 1);
    assert_eq!(
        leadership.events(),
        [
            Event::Begun("test-task".to_owned()),
            Event::Recorded(UNIX_EPOCH),
            Event::Committed,
        ]
    );
}

#[tokio::test]
async fn a_batch_without_the_lock_is_skipped_and_its_work_never_runs() {
    let leadership = Arc::new(FakeSingletonLeadership::new(&[], Step::Follow));
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(work.runs.load(Ordering::SeqCst), 0);
    assert_eq!(leadership.events(), [Event::Begun("test-task".to_owned())]);
}

#[tokio::test]
async fn failing_work_rolls_the_batch_back_without_recording_a_run() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork {
        fail: true,
        ..CountingWork::default()
    });

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(
        leadership.events(),
        [Event::Begun("test-task".to_owned()), Event::RolledBack]
    );
}

#[tokio::test]
async fn a_run_that_cannot_be_recorded_rolls_the_batch_back() {
    let leadership = Arc::new(FakeSingletonLeadership::new(
        &[Step::LeadFailingRecord],
        Step::Lead,
    ));
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::RolledBack);
    assert_eq!(leadership.events().last(), Some(&Event::RolledBack));
}

#[tokio::test]
async fn a_commit_that_fails_is_a_failed_batch() {
    let leadership = Arc::new(FakeSingletonLeadership::new(
        &[Step::LeadFailingCommit],
        Step::Lead,
    ));
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::Failed);
}

#[tokio::test]
async fn an_unavailable_storage_is_a_failed_batch_without_work() {
    let leadership = Arc::new(FakeSingletonLeadership::new(&[], Step::Fail));
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;

    assert_eq!(outcome, BatchOutcome::Failed);
    assert_eq!(work.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn the_loop_retries_at_its_interval_and_takes_over_when_the_lock_frees() {
    let leadership = Arc::new(FakeSingletonLeadership::new(
        &[Step::Follow, Step::Follow],
        Step::Lead,
    ));
    let work = Arc::new(CountingWork::default());
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(singleton(&leadership, &work).run(stopping));

    tokio::time::sleep(INTERVAL * 2 + Duration::from_millis(500)).await;
    stop.send_replace(true);
    handle.await.unwrap();

    assert_eq!(work.runs.load(Ordering::SeqCst), 1);
    assert_eq!(leadership.events().last(), Some(&Event::Committed));
}

#[tokio::test(start_paused = true)]
async fn the_loop_ends_when_the_stop_flag_is_set_during_the_pause() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(singleton(&leadership, &work).run(stopping));
    tokio::task::yield_now().await;

    stop.send_replace(true);
    handle.await.unwrap();

    assert_eq!(work.runs.load(Ordering::SeqCst), 1);
}

/// Work that counts how often it heard that its loop stopped.
#[derive(Debug, Default)]
struct StoppingWork {
    stops: AtomicUsize,
}

#[async_trait::async_trait]
impl SingletonWork for StoppingWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        Ok(())
    }

    async fn on_stop(&self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn work_hears_once_that_its_loop_stopped() {
    let work = Arc::new(StoppingWork::default());
    let singleton = SingletonLoop::new(
        TASK,
        interval(),
        Arc::new(FakeSingletonLeadership::leading()),
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        Arc::<StoppingWork>::clone(&work),
    );
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(singleton.run(stopping));
    tokio::task::yield_now().await;
    assert_eq!(work.stops.load(Ordering::SeqCst), 0);

    stop.send_replace(true);
    handle.await.unwrap();

    assert_eq!(work.stops.load(Ordering::SeqCst), 1);
}

/// Work whose batch never ends and that may be abandoned when the service stops.
#[derive(Debug, Default)]
struct EndlessWork {
    started: AtomicUsize,
    stops: AtomicUsize,
}

#[async_trait::async_trait]
impl SingletonWork for EndlessWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    async fn on_stop(&self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
    }

    fn interruptible(&self) -> bool {
        true
    }
}

#[tokio::test(start_paused = true)]
async fn an_interruptible_batch_in_flight_is_abandoned_when_the_service_stops() {
    let work = Arc::new(EndlessWork::default());
    let singleton = SingletonLoop::new(
        TASK,
        interval(),
        Arc::new(FakeSingletonLeadership::leading()),
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        Arc::<EndlessWork>::clone(&work),
    );
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(singleton.run(stopping));
    tokio::task::yield_now().await;
    assert_eq!(work.started.load(Ordering::SeqCst), 1);

    stop.send_replace(true);
    handle.await.unwrap();

    assert_eq!(work.started.load(Ordering::SeqCst), 1);
    assert_eq!(work.stops.load(Ordering::SeqCst), 1);
}

#[test]
fn a_batch_runs_to_its_end_unless_the_work_says_otherwise() {
    assert!(!CountingWork::default().interruptible());
}

#[tokio::test]
async fn the_loop_runs_no_batch_when_it_starts_stopped() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());
    let (_stop, stopping) = watch::channel(true);

    singleton(&leadership, &work).run(stopping).await;

    assert_eq!(work.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_loop_ends_when_the_stop_flag_has_no_sender_left() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());
    let (stop, stopping) = watch::channel(false);
    drop(stop);

    singleton(&leadership, &work).run(stopping).await;

    assert_eq!(work.runs.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_wake_up_starts_the_next_batch_before_the_interval_ends() {
    let leadership = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());
    let wake = Arc::new(Notify::new());
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(
        singleton(&leadership, &work)
            .with_wake(Arc::clone(&wake))
            .run(stopping),
    );
    tokio::task::yield_now().await;
    assert_eq!(work.runs.load(Ordering::SeqCst), 1);

    wake.notify_one();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    stop.send_replace(true);
    handle.await.unwrap();

    assert_eq!(work.runs.load(Ordering::SeqCst), 2);
}

/// Work that counts the batches that another replica led.
#[derive(Debug, Default)]
struct FollowerWork {
    followed: AtomicUsize,
}

#[async_trait::async_trait]
impl SingletonWork for FollowerWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        Ok(())
    }

    async fn on_follower(&self) {
        self.followed.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn work_hears_of_a_batch_that_another_replica_leads() {
    let work = Arc::new(FollowerWork::default());
    let singleton = SingletonLoop::new(
        TASK,
        interval(),
        Arc::new(FakeSingletonLeadership::new(&[], Step::Follow)),
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        Arc::<FollowerWork>::clone(&work),
    );

    let outcome = singleton.run_batch().await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(work.followed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn work_that_ignores_followers_runs_unchanged_on_a_skipped_batch() {
    let leadership = Arc::new(FakeSingletonLeadership::new(&[], Step::Follow));
    let work = Arc::new(CountingWork::default());

    let outcome = singleton(&leadership, &work).run_batch().await;
    CountingWork::default().on_follower().await;

    assert_eq!(outcome, BatchOutcome::Skipped);
    assert_eq!(work.runs.load(Ordering::SeqCst), 0);
}

#[test]
fn a_clamped_interval_stays_between_one_millisecond_and_ten_seconds() {
    assert_eq!(
        SingletonInterval::clamped(Duration::from_millis(100)).get(),
        Duration::from_millis(100)
    );
    assert_eq!(
        SingletonInterval::clamped(Duration::ZERO).get(),
        Duration::from_millis(1)
    );
    assert_eq!(
        SingletonInterval::clamped(Duration::from_secs(60)).get(),
        MAX_SINGLETON_INTERVAL
    );
}
