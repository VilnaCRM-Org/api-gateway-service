//! The singleton loop helper: runs one batch per interval of a task that exactly one replica may
//! run at a time, and skips the batch on a replica that does not hold the lock (FR-45).
//!
//! A replica without the lock does nothing until the next interval; the interval is at most
//! [`MAX_SINGLETON_INTERVAL`], so a new leader takes over within one retry interval after the
//! leader stopped.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{LeaderBatch, Leadership, SingletonLeadership, SingletonTask};
use shared_domain::{BoxError, Clock};
use tokio::sync::watch;

/// The longest interval at which a replica without the lock retries.
pub const MAX_SINGLETON_INTERVAL: Duration = Duration::from_secs(10);

/// The interval of a singleton task is zero or longer than [`MAX_SINGLETON_INTERVAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the singleton interval {requested:?} is zero or longer than 10s")]
pub struct InvalidSingletonInterval {
    /// The refused interval.
    pub requested: Duration,
}

/// How often a singleton task runs a batch, and how often a replica without the lock retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingletonInterval(Duration);

impl SingletonInterval {
    /// An interval of `interval`.
    ///
    /// # Errors
    ///
    /// [`InvalidSingletonInterval`] when it is zero or longer than [`MAX_SINGLETON_INTERVAL`].
    pub fn new(interval: Duration) -> Result<Self, InvalidSingletonInterval> {
        if interval.is_zero() || interval > MAX_SINGLETON_INTERVAL {
            return Err(InvalidSingletonInterval {
                requested: interval,
            });
        }
        Ok(Self(interval))
    }

    /// The interval as a duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// The work of one batch of a singleton task. It writes through the batch it receives, which is
/// the transaction that holds the lock; an error rolls everything it wrote back.
#[async_trait::async_trait]
pub trait SingletonWork: std::fmt::Debug + Send + Sync {
    /// Runs one batch.
    ///
    /// # Errors
    ///
    /// Any error of the work; the batch is rolled back.
    async fn run(&self, batch: &mut dyn LeaderBatch) -> Result<(), BoxError>;
}

/// How one attempt at a batch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// This replica led the batch and committed it.
    Committed,
    /// Another replica leads: the batch was skipped.
    Skipped,
    /// This replica led the batch, but the work or the record of the run failed: rolled back.
    RolledBack,
    /// The storage failed before the batch started or while it committed; nothing was committed.
    Failed,
}

/// A singleton task: its batches, fenced by the leadership, repeated at its interval.
#[derive(Debug)]
pub struct SingletonLoop {
    task: SingletonTask,
    interval: SingletonInterval,
    leadership: Arc<dyn SingletonLeadership>,
    clock: Arc<dyn Clock>,
    work: Arc<dyn SingletonWork>,
}

impl SingletonLoop {
    /// A loop that runs `work` as the batches of `task`.
    #[must_use]
    pub fn new(
        task: SingletonTask,
        interval: SingletonInterval,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
        work: Arc<dyn SingletonWork>,
    ) -> Self {
        Self {
            task,
            interval,
            leadership,
            clock,
            work,
        }
    }

    /// The name of the task, for the log entries of the supervisor.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.task.name()
    }

    /// Tries one batch: leads and runs it when the lock is free, skips it otherwise.
    pub async fn run_batch(&self) -> BatchOutcome {
        match self.leadership.begin(&self.task).await {
            Ok(Leadership::Leader(batch)) => self.lead(batch).await,
            Ok(Leadership::Follower) => BatchOutcome::Skipped,
            Err(error) => {
                log_unavailable(self.task.name(), &error);
                BatchOutcome::Failed
            }
        }
    }

    /// Runs batches until the stop flag is set or its sender is gone. A batch in flight when the
    /// flag is set ends first, by a commit or a rollback.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        while !*shutdown.borrow() {
            self.run_batch().await;
            if !self.pause(&mut shutdown).await {
                break;
            }
        }
    }

    /// Waits for the interval; `false` when the service is stopping instead.
    async fn pause(&self, shutdown: &mut watch::Receiver<bool>) -> bool {
        tokio::select! {
            () = tokio::time::sleep(self.interval.get()) => true,
            stopping = shutdown.wait_for(|stopping| *stopping) => {
                drop(stopping);
                false
            }
        }
    }

    async fn lead(&self, mut batch: Box<dyn LeaderBatch>) -> BatchOutcome {
        match self.work_and_record(batch.as_mut()).await {
            Ok(()) => self.commit(batch).await,
            Err(error) => {
                log_rolled_back(self.task.name(), &error);
                self.rollback(batch).await
            }
        }
    }

    async fn work_and_record(&self, batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.work.run(batch).await?;
        batch.record_run(self.clock.now()).await?;
        Ok(())
    }

    async fn commit(&self, batch: Box<dyn LeaderBatch>) -> BatchOutcome {
        match batch.commit().await {
            Ok(()) => BatchOutcome::Committed,
            Err(error) => {
                log_unavailable(self.task.name(), &error);
                BatchOutcome::Failed
            }
        }
    }

    async fn rollback(&self, batch: Box<dyn LeaderBatch>) -> BatchOutcome {
        if let Err(error) = batch.rollback().await {
            log_unavailable(self.task.name(), &error);
        }
        BatchOutcome::RolledBack
    }
}

fn log_unavailable(task: &str, error: &dyn std::error::Error) {
    tracing::warn!(task, error = %error, "singleton leadership storage failed");
}

fn log_rolled_back(task: &str, error: &BoxError) {
    tracing::warn!(task, error = %error, "singleton batch rolled back");
}

#[cfg(test)]
mod tests;
