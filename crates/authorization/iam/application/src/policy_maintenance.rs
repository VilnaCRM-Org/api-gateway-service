//! The `PolicyMaintenance` singleton: every `MAINTENANCE_INTERVAL` it runs one pass of the
//! maintenance inside a fenced batch (FR-43, FR-45).
//!
//! The batch that leads the task holds the advisory lock of the task for the whole pass, so of
//! several replicas only the lock holder purges, removes and anchors. The pass itself commits
//! through the unit of work and the maintenance store, each in its own transaction, while the lock
//! is held.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{LeaderBatch, SingletonLeadership, SingletonTask, TaskStateRepository};
use shared_domain::{BoxError, Clock, CommandHandler as _};

use crate::command::run_maintenance::{RunMaintenanceCommand, RunMaintenanceCommandHandler};
use crate::singleton_loop::{
    InvalidSingletonInterval, MAX_SINGLETON_INTERVAL, SingletonInterval, SingletonLoop,
    SingletonWork,
};

/// The settings of the maintenance task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceSettings {
    /// `MAINTENANCE_INTERVAL`: how often a pass runs.
    pub interval: Duration,
    /// `ORPHANED_GRANT_RETENTION`: how long an orphaned grant is kept before it is purged.
    pub orphaned_grant_retention: Duration,
}

impl Default for MaintenanceSettings {
    /// A pass every 10 minutes, and orphaned grants kept for 90 days.
    fn default() -> Self {
        Self {
            interval: Duration::from_mins(10),
            orphaned_grant_retention: Duration::from_hours(2_160),
        }
    }
}

/// The maintenance task: dispatches [`RunMaintenanceCommand`] when a pass is due.
#[derive(Debug)]
pub struct PolicyMaintenance {
    handler: RunMaintenanceCommandHandler,
    task_states: Arc<dyn TaskStateRepository>,
    settings: MaintenanceSettings,
}

impl PolicyMaintenance {
    /// The task: its name in the log and in `iam_task_state`, and the constant that the advisory
    /// lock of its batches is taken on.
    pub const TASK: SingletonTask = SingletonTask::new("policy-maintenance", 7_008);

    /// The task over the handler of a pass, the state that the committed batches left and the
    /// settings.
    #[must_use]
    pub const fn new(
        handler: RunMaintenanceCommandHandler,
        task_states: Arc<dyn TaskStateRepository>,
        settings: MaintenanceSettings,
    ) -> Self {
        Self {
            handler,
            task_states,
            settings,
        }
    }

    /// The loop that runs the task. It polls at `MAINTENANCE_INTERVAL`, or at the longest retry
    /// interval of a singleton when that is shorter, so that a new leader takes over within one
    /// retry interval; a poll that finds no pass due ends without running anything.
    ///
    /// # Errors
    ///
    /// [`InvalidSingletonInterval`] when `MAINTENANCE_INTERVAL` is zero.
    pub fn into_loop(
        self,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
    ) -> Result<SingletonLoop, InvalidSingletonInterval> {
        let poll = SingletonInterval::new(self.settings.interval.min(MAX_SINGLETON_INTERVAL))?;
        Ok(SingletonLoop::new(
            Self::TASK,
            poll,
            leadership,
            clock,
            Arc::new(self),
        ))
    }

    /// Whether the interval has passed since the last committed pass; a time before the last pass
    /// (a clock that went back) is not due.
    async fn due(&self, now: SystemTime) -> Result<bool, BoxError> {
        let last = self.task_states.find(Self::TASK.name()).await?;
        Ok(last.is_none_or(|state| {
            now.duration_since(state.last_run_at)
                .is_ok_and(|elapsed| elapsed >= self.settings.interval)
        }))
    }
}

#[async_trait::async_trait]
impl SingletonWork for PolicyMaintenance {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.handler
            .handle(RunMaintenanceCommand {
                orphaned_grant_retention: self.settings.orphaned_grant_retention,
            })
            .await?;
        Ok(())
    }

    async fn is_due(&self, now: SystemTime) -> Result<bool, BoxError> {
        self.due(now).await
    }
}

#[cfg(test)]
mod tests;
