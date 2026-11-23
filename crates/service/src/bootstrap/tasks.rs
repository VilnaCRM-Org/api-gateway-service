//! The per-replica background tasks of the service and the supervisor that stops them (FR-45).
//!
//! Every replica runs its own copy of each task. [`start_tasks`] builds the supervisor with no
//! task yet: the stories that add a task register it in [`start_tasks`]. A task takes the stop
//! flag of the service and ends when it is set; [`TaskSupervisor::stop`] waits for every task for
//! the grace period and aborts what is left.

use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;

use super::Adapters;

/// Where the supervisor runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskMode {
    /// Under `service serve`, until SIGTERM or SIGINT.
    Serve,
    /// Inside a test process that builds the application from the adapters.
    Test,
}

/// How the tasks ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStop {
    /// Every task ended within the grace period.
    Drained,
    /// The grace period ended with tasks running; they were aborted.
    Aborted {
        /// The number of tasks that were aborted.
        remaining: usize,
    },
}

/// Runs the per-replica tasks and stops them.
#[derive(Debug)]
pub struct TaskSupervisor {
    mode: TaskMode,
    shutdown: watch::Receiver<bool>,
    tasks: JoinSet<()>,
}

impl TaskSupervisor {
    /// A supervisor without tasks; `shutdown` is the stop flag that its tasks watch.
    #[must_use]
    pub fn new(mode: TaskMode, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            mode,
            shutdown,
            tasks: JoinSet::new(),
        }
    }

    /// Starts `task`, which receives the stop flag and must end when it is set.
    pub fn spawn<F, Fut>(&mut self, name: &'static str, task: F)
    where
        F: FnOnce(watch::Receiver<bool>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        tracing::debug!(task = name, mode = ?self.mode, "task started");
        self.tasks.spawn(task(self.shutdown.clone()));
    }

    /// The number of tasks that run.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether no task runs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Waits until every task ended or `grace` elapsed, then aborts the tasks that are left.
    ///
    /// The caller sets the stop flag first.
    pub async fn stop(mut self, grace: Duration) -> TaskStop {
        let ended = tokio::time::timeout(grace, Self::join_all(&mut self.tasks)).await;
        if ended.is_ok() {
            return TaskStop::Drained;
        }
        let remaining = self.tasks.len();
        self.tasks.abort_all();
        Self::join_all(&mut self.tasks).await;
        TaskStop::Aborted { remaining }
    }

    async fn join_all(tasks: &mut JoinSet<()>) {
        while let Some(joined) = tasks.join_next().await {
            Self::report(joined);
        }
    }

    /// Logs a task that panicked; a task that was aborted is no failure.
    fn report(joined: Result<(), tokio::task::JoinError>) {
        if let Err(error) = joined
            && !error.is_cancelled()
        {
            log_failed(&error);
        }
    }
}

fn log_failed(error: &tokio::task::JoinError) {
    tracing::error!(error = %error, "task failed");
}

/// Starts the per-replica tasks of the service. No story has registered one yet.
///
/// `shutdown` is the stop flag of the service: tasks end when it is set.
#[must_use]
pub fn start_tasks(
    _adapters: &Adapters,
    mode: TaskMode,
    shutdown: watch::Receiver<bool>,
) -> TaskSupervisor {
    let supervisor = TaskSupervisor::new(mode, shutdown);
    tracing::debug!(?mode, tasks = supervisor.len(), "tasks started");
    supervisor
}

#[cfg(test)]
mod tests;
