//! The per-replica background tasks of the service and the supervisor that stops them (FR-45).
//!
//! Every replica runs its own copy of each per-replica task. A singleton task is a
//! [`SingletonLoop`]: every replica runs the loop, and the advisory lock of its leadership lets
//! exactly one of them run each batch. [`start_tasks`] builds the supervisor and, under
//! `service serve`, starts the singleton set ([`singleton_set`]); the stories that add a task
//! register it there. A task takes the stop
//! flag of the service and ends when it is set; [`TaskSupervisor::stop`] waits for every task for
//! the grace period and aborts what is left.

use std::time::Duration;

use iam_application::SingletonLoop;
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

    /// Starts a singleton task: its loop runs on this replica, and its leadership decides which
    /// replica runs each batch.
    pub fn spawn_singleton(&mut self, singleton: SingletonLoop) {
        self.spawn(singleton.name(), |shutdown| singleton.run(shutdown));
    }

    /// Starts every task of `singletons`.
    pub fn spawn_singletons(&mut self, singletons: Vec<SingletonLoop>) {
        for singleton in singletons {
            self.spawn_singleton(singleton);
        }
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

/// The singleton tasks that `service serve` runs. No story has registered one yet; there is no
/// `service worker` mode, so the set runs inside `serve`.
#[must_use]
pub const fn singleton_set(_adapters: &Adapters) -> Vec<SingletonLoop> {
    Vec::new()
}

/// Starts the tasks of the service: the singleton set under `service serve`. No other story has
/// registered a task yet.
///
/// `shutdown` is the stop flag of the service: tasks end when it is set.
#[must_use]
pub fn start_tasks(
    adapters: &Adapters,
    mode: TaskMode,
    shutdown: watch::Receiver<bool>,
) -> TaskSupervisor {
    let mut supervisor = TaskSupervisor::new(mode, shutdown);
    if mode == TaskMode::Serve {
        supervisor.spawn_singletons(singleton_set(adapters));
    }
    log_started(mode, supervisor.len());
    supervisor
}

fn log_started(mode: TaskMode, tasks: usize) {
    tracing::debug!(?mode, tasks, "tasks started");
}

#[cfg(test)]
mod tests;
