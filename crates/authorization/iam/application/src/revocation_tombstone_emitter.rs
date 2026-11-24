//! The `RevocationTombstoneEmitter` singleton: every `MAINTENANCE_INTERVAL` it commits the
//! tombstones of the revocation records that are past their prune-after instant (FR-79).
//!
//! The batch that leads the task holds the advisory lock of the task for the whole run, so of
//! several replicas only the lock holder emits. Gateway pods never prune revocation state by
//! clock; they drop an entry only when its tombstone is applied.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{LeaderBatch, SingletonLeadership, SingletonTask, TaskStateRepository};
use shared_domain::{BoxError, Clock, CommandHandler as _};

use crate::command::emit_revocation_tombstones::{
    EmitRevocationTombstonesCommand, EmitRevocationTombstonesCommandHandler,
};
use crate::singleton_loop::{
    InvalidSingletonInterval, MAX_SINGLETON_INTERVAL, SingletonInterval, SingletonLoop,
    SingletonWork,
};

/// The revocation tombstone task: dispatches [`EmitRevocationTombstonesCommand`] when a run is
/// due.
#[derive(Debug)]
pub struct RevocationTombstoneEmitter {
    handler: EmitRevocationTombstonesCommandHandler,
    task_states: Arc<dyn TaskStateRepository>,
    interval: Duration,
}

impl RevocationTombstoneEmitter {
    /// The task: its name in the log and in `iam_task_state`, and the constant that the advisory
    /// lock of its batches is taken on.
    pub const TASK: SingletonTask = SingletonTask::new("revocation-tombstone-emitter", 7_010);

    /// The task over the handler of a run, the state that the committed batches left and
    /// `MAINTENANCE_INTERVAL`.
    #[must_use]
    pub const fn new(
        handler: EmitRevocationTombstonesCommandHandler,
        task_states: Arc<dyn TaskStateRepository>,
        interval: Duration,
    ) -> Self {
        Self {
            handler,
            task_states,
            interval,
        }
    }

    /// The loop that runs the task. It polls at the interval, or at the longest retry interval of
    /// a singleton when that is shorter, so that a new leader takes over within one retry
    /// interval; a poll that finds no run due ends without running anything.
    ///
    /// # Errors
    ///
    /// [`InvalidSingletonInterval`] when the interval is zero.
    pub fn into_loop(
        self,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
    ) -> Result<SingletonLoop, InvalidSingletonInterval> {
        let poll = SingletonInterval::new(self.interval.min(MAX_SINGLETON_INTERVAL))?;
        Ok(SingletonLoop::new(
            Self::TASK,
            poll,
            leadership,
            clock,
            Arc::new(self),
        ))
    }

    /// Whether the interval has passed since the last committed run; a time before the last run
    /// (a clock that went back) is not due.
    async fn due(&self, now: SystemTime) -> Result<bool, BoxError> {
        let last = self.task_states.find(Self::TASK.name()).await?;
        Ok(last.is_none_or(|state| {
            now.duration_since(state.last_run_at)
                .is_ok_and(|elapsed| elapsed >= self.interval)
        }))
    }
}

#[async_trait::async_trait]
impl SingletonWork for RevocationTombstoneEmitter {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.handler.handle(EmitRevocationTombstonesCommand).await?;
        Ok(())
    }

    async fn is_due(&self, now: SystemTime) -> Result<bool, BoxError> {
        self.due(now).await
    }
}

#[cfg(test)]
mod tests;
