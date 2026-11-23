use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
