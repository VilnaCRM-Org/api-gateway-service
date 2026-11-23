use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use iam_application::{SingletonInterval, SingletonLoop, SingletonWork};
use iam_domain::{LeaderBatch, SingletonLeadership, SingletonTask};
use test_support::clock::FixedClock;
use test_support::singleton_leadership::FakeSingletonLeadership;
use tokio::sync::watch;

use super::{TaskMode, TaskStop, TaskSupervisor};

const GRACE: Duration = Duration::from_secs(5);

#[test]
fn a_new_supervisor_runs_no_task() {
    let (_stop, stopping) = watch::channel(false);

    let supervisor = TaskSupervisor::new(TaskMode::Test, stopping);

    assert!(supervisor.is_empty());
    assert_eq!(supervisor.len(), 0);
}

#[tokio::test]
async fn a_task_that_watches_the_flag_ends_within_the_grace_period() {
    let (stop, stopping) = watch::channel(false);
    let ended = Arc::new(AtomicBool::new(false));
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, stopping);
    let flag = Arc::clone(&ended);
    supervisor.spawn("watcher", async move |mut shutdown| {
        drop(shutdown.wait_for(|stopping| *stopping).await);
        flag.store(true, Ordering::SeqCst);
    });
    assert_eq!(supervisor.len(), 1);

    stop.send_replace(true);
    let outcome = supervisor.stop(GRACE).await;

    assert_eq!(outcome, TaskStop::Drained);
    assert!(ended.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_task_that_ignores_the_flag_is_aborted_when_the_grace_period_ends() {
    let (stop, stopping) = watch::channel(false);
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, stopping);
    supervisor.spawn("stubborn", |_shutdown| std::future::pending());

    stop.send_replace(true);
    let outcome = supervisor.stop(GRACE).await;

    assert_eq!(outcome, TaskStop::Aborted { remaining: 1 });
}

#[tokio::test]
async fn a_task_that_panics_does_not_stop_the_others_from_draining() {
    let (stop, stopping) = watch::channel(false);
    let mut supervisor = TaskSupervisor::new(TaskMode::Test, stopping);
    supervisor.spawn("panicking", async |_shutdown| panic!("a task failed"));
    supervisor.spawn("watcher", async move |mut shutdown| {
        drop(shutdown.wait_for(|stopping| *stopping).await);
    });

    stop.send_replace(true);

    assert_eq!(supervisor.stop(GRACE).await, TaskStop::Drained);
}

/// Work that counts its batches.
#[derive(Debug, Default)]
struct CountingWork {
    runs: AtomicUsize,
}

#[async_trait::async_trait]
impl SingletonWork for CountingWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), shared_domain::BoxError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn a_singleton_task_runs_its_batch_and_ends_with_the_stop_flag() {
    let (stop, stopping) = watch::channel(false);
    let leadership: Arc<dyn SingletonLeadership> = Arc::new(FakeSingletonLeadership::leading());
    let work = Arc::new(CountingWork::default());
    let task_work: Arc<dyn SingletonWork> = Arc::<CountingWork>::clone(&work);
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, stopping);
    supervisor.spawn_singletons(vec![SingletonLoop::new(
        SingletonTask::new("test-singleton", 1),
        SingletonInterval::new(Duration::from_secs(1)).unwrap(),
        leadership,
        Arc::new(FixedClock::at(UNIX_EPOCH)),
        task_work,
    )]);
    assert_eq!(supervisor.len(), 1);
    tokio::task::yield_now().await;

    stop.send_replace(true);
    let outcome = supervisor.stop(GRACE).await;

    assert_eq!(outcome, TaskStop::Drained);
    assert_eq!(work.runs.load(Ordering::SeqCst), 1);
}
