//! The per-replica background tasks of the service and the supervisor that stops them (FR-45).
//!
//! Every replica runs its own copy of each per-replica task. A singleton task is a
//! [`SingletonLoop`]: every replica runs the loop, and the advisory lock of its leadership lets
//! exactly one of them run each batch. [`start_tasks`] builds the supervisor, starts the rejected-attempt
//! writer and, under `service serve`, starts the singleton set ([`singleton_set`]); the stories that add a task
//! register it there. A task takes the stop
//! flag of the service and ends when it is set; [`TaskSupervisor::stop`] waits for every task for
//! the grace period and aborts what is left.

use std::sync::Arc;
use std::time::Duration;

use iam_application::{
    AntiEntropyChecker, BulkChunkRouter, BulkOperationRunner, BulkRunnerPorts,
    InvalidSingletonInterval, OutboxRelay, PolicyMaintenance, RejectedAttemptWriter,
    ResyncChunkCommitter, ResyncPorts, RoleDeletionChunkCommitter, RoleDeletionPorts,
    RunMaintenanceCommandHandler, SingletonLoop,
};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::Instrument as _;

use super::{Adapters, AntiEntropyAdapters, OutboxRelayAdapters, forward_notifications};

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

/// The singleton tasks that `service serve` runs: maintenance, the outbox relay, anti-entropy and
/// the bulk operation runner.
///
/// There is no `service worker` mode, so the set runs inside `serve`; the stories that add a task
/// extend it here.
#[must_use]
pub fn singleton_set(adapters: &Adapters) -> Vec<SingletonLoop> {
    let mut set = Vec::new();
    set.extend(maintenance_loop(adapters));
    set.extend(
        adapters
            .outbox_relay
            .as_ref()
            .map(|relay| relay_loop(adapters, relay)),
    );
    set.extend(
        adapters
            .outbox_relay
            .as_ref()
            .and_then(|relay| relay.anti_entropy.as_ref())
            .map(|anti_entropy| anti_entropy_loop(adapters, anti_entropy)),
    );
    set.push(bulk_loop(adapters));
    set
}

/// The loop of the bulk operation runner: it commits the oldest unfinished bulk operation chunk by
/// chunk, at most `BULK_MAX_RECORDS_PER_SECOND` records per second (Story 7.9).
fn bulk_loop(adapters: &Adapters) -> SingletonLoop {
    let committer = RoleDeletionChunkCommitter::new(
        RoleDeletionPorts {
            roles: Arc::clone(&adapters.roles),
            user_roles: Arc::clone(&adapters.user_roles),
            targets: Arc::clone(&adapters.bulk_targets),
            policy_epochs: Arc::clone(&adapters.policy_epochs),
            unit_of_work: Arc::clone(&adapters.unit_of_work),
            ids: Arc::clone(&adapters.uuid_generator),
        },
        adapters.bulk.chunker,
    );
    let resync = ResyncChunkCommitter::new(
        ResyncPorts {
            policy_epochs: Arc::clone(&adapters.policy_epochs),
            inventory: Arc::clone(&adapters.policy_inventory),
            unit_of_work: Arc::clone(&adapters.unit_of_work),
            ids: Arc::clone(&adapters.uuid_generator),
        },
        adapters.bulk.chunker,
    );
    BulkOperationRunner::new(
        BulkRunnerPorts {
            operations: Arc::clone(&adapters.bulk_operations),
            committer: Arc::new(BulkChunkRouter::new(Arc::new(committer), Arc::new(resync))),
            clock: Arc::clone(&adapters.clock),
            ids: Arc::clone(&adapters.uuid_generator),
        },
        adapters.bulk.pacing,
    )
    .into_loop(
        Arc::clone(&adapters.singleton_leadership),
        Arc::clone(&adapters.clock),
    )
}

/// The loop of the anti-entropy task: a head check every `ANTI_ENTROPY_HEAD_INTERVAL` (polled at
/// most every 10 seconds) and a shadow bootstrap every `ANTI_ENTROPY_FULL_INTERVAL`.
fn anti_entropy_loop(adapters: &Adapters, anti_entropy: &AntiEntropyAdapters) -> SingletonLoop {
    AntiEntropyChecker::new(
        anti_entropy.ports.clone(),
        Arc::clone(&adapters.clock),
        anti_entropy.settings,
        Arc::clone(&anti_entropy.counters),
        Arc::clone(&anti_entropy.hold),
    )
    .into_loop(
        Arc::clone(&adapters.singleton_leadership),
        Arc::clone(&adapters.clock),
    )
}

/// The loop of the outbox relay: a fenced batch every 100 ms, or as soon as the listener of
/// `iam_outbox` reports a committed change.
fn relay_loop(adapters: &Adapters, relay: &OutboxRelayAdapters) -> SingletonLoop {
    let task = OutboxRelay::new(
        relay.ports.clone(),
        Arc::clone(&adapters.clock),
        relay.settings,
        Arc::clone(&relay.leading),
    );
    let task = match &relay.anti_entropy {
        Some(anti_entropy) => task.with_hold(Arc::clone(&anti_entropy.hold)),
        None => task,
    };
    task.into_loop(
        Arc::clone(&adapters.singleton_leadership),
        Arc::clone(&adapters.clock),
        Arc::clone(&relay.wake),
    )
}

/// The loop of the maintenance task over the adapters of the application; none when the interval
/// of the task is zero, which the configuration refuses.
fn maintenance_loop(adapters: &Adapters) -> Option<SingletonLoop> {
    let handler = RunMaintenanceCommandHandler::new(
        Arc::clone(&adapters.maintenance_store),
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let task = PolicyMaintenance::new(
        handler,
        Arc::clone(&adapters.task_states),
        adapters.maintenance,
    );
    match task.into_loop(
        Arc::clone(&adapters.singleton_leadership),
        Arc::clone(&adapters.clock),
    ) {
        Ok(singleton) => Some(singleton),
        Err(error) => {
            log_not_started(&error);
            None
        }
    }
}

fn log_not_started(error: &InvalidSingletonInterval) {
    tracing::error!(error = %error, "the maintenance task is not started");
}

/// The writer that appends the buffered refusals of IAM's operations to the audit chain: it runs on
/// every replica, in every mode, because the append itself takes the chain-head lock.
fn rejected_attempt_writer(adapters: &Adapters) -> RejectedAttemptWriter {
    RejectedAttemptWriter::new(
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.security_audit_log),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    )
}

/// Starts the tasks of the service: the rejected-attempt writer in every mode, and under
/// `service serve` the singleton set and the listener of the outbox wake-up.
///
/// `shutdown` is the stop flag of the service: tasks end when it is set.
#[must_use]
pub fn start_tasks(
    adapters: &Adapters,
    mode: TaskMode,
    shutdown: watch::Receiver<bool>,
) -> TaskSupervisor {
    let mut supervisor = TaskSupervisor::new(mode, shutdown);
    let writer = rejected_attempt_writer(adapters);
    supervisor.spawn("rejected-attempt-writer", |stop| writer.run(stop));
    if mode == TaskMode::Serve {
        supervisor.spawn_singletons(singleton_set(adapters));
        if let Some(relay) = adapters.outbox_relay.clone() {
            // The listener writes inside an `outbox.listener` span, so its entries are told apart
            // from those of a request.
            supervisor.spawn("outbox-listener", |shutdown| {
                forward_notifications(relay, shutdown)
                    .instrument(tracing::info_span!("outbox.listener"))
            });
        }
    }
    log_started(mode, supervisor.len());
    supervisor
}

fn log_started(mode: TaskMode, tasks: usize) {
    tracing::debug!(?mode, tasks, "tasks started");
}

#[cfg(test)]
mod tests;
