use std::time::Duration;

use tokio::sync::watch;

use super::{Shutdown, drain};
use crate::bootstrap::{TaskMode, TaskSupervisor};

const GRACE: Duration = Duration::from_secs(1);

fn stopped_supervisor() -> (watch::Sender<bool>, TaskSupervisor) {
    let (stop, stopping) = watch::channel(false);
    (stop, TaskSupervisor::new(TaskMode::Test, stopping))
}

#[tokio::test]
async fn a_server_and_tasks_that_end_in_time_are_a_drained_shutdown() {
    let (stop, tasks) = stopped_supervisor();
    let server = tokio::spawn(async { Ok(()) });
    stop.send_replace(true);

    assert_eq!(
        drain(server, tasks, GRACE).await.unwrap(),
        Shutdown::Drained
    );
}

#[tokio::test(start_paused = true)]
async fn a_task_that_outlives_the_grace_period_forces_the_shutdown_of_a_drained_server() {
    let (stop, mut tasks) = stopped_supervisor();
    tasks.spawn("stubborn", |_shutdown| std::future::pending());
    let server = tokio::spawn(async { Ok(()) });
    stop.send_replace(true);

    assert_eq!(drain(server, tasks, GRACE).await.unwrap(), Shutdown::Forced);
}

#[tokio::test]
async fn a_server_that_fails_while_draining_is_an_error() {
    let (stop, tasks) = stopped_supervisor();
    let server = tokio::spawn(async { Err(std::io::Error::other("the listener failed")) });
    stop.send_replace(true);

    assert!(drain(server, tasks, GRACE).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_server_that_outlives_the_grace_period_is_a_forced_shutdown() {
    let (stop, tasks) = stopped_supervisor();
    let server = tokio::spawn(std::future::pending());
    stop.send_replace(true);

    assert_eq!(drain(server, tasks, GRACE).await.unwrap(), Shutdown::Forced);
}
