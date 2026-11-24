//! The singleton loop helper: runs one batch per interval of a task that exactly one replica may
//! run at a time, and skips the batch on a replica that does not hold the lock (FR-45).
//!
//! A replica without the lock does nothing until the next interval; the interval is at most
//! [`MAX_SINGLETON_INTERVAL`], so a new leader takes over within one retry interval after the
//! leader stopped.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{LeaderBatch, Leadership, SingletonLeadership, SingletonTask};
use shared_domain::{BoxError, Clock};
use tokio::sync::{Notify, watch};
use tracing::Instrument as _;

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

    /// An interval of `interval` held between 1 millisecond and [`MAX_SINGLETON_INTERVAL`]; for
    /// constants that are valid by construction.
    #[must_use]
    pub fn clamped(interval: Duration) -> Self {
        Self(interval.clamp(Duration::from_millis(1), MAX_SINGLETON_INTERVAL))
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

    /// Whether a batch that this replica leads at `now` has work to do. A batch whose work is not
    /// due ends without running the work and without recording a run, so a task whose own
    /// period is longer than the retry interval is polled at the retry interval and runs once per
    /// period. Every batch is due unless the work says otherwise.
    ///
    /// # Errors
    ///
    /// Any error of the check; the batch is rolled back.
    async fn is_due(&self, _now: SystemTime) -> Result<bool, BoxError> {
        Ok(true)
    }

    /// Called when another replica leads the batch that this replica skips, so that work that
    /// holds a resource only while it leads can let it go. Does nothing unless the work says
    /// otherwise.
    async fn on_follower(&self) {}

    /// Called once when the loop stops, after its last batch, so that work that holds a resource
    /// can release it. Does nothing unless the work says otherwise.
    async fn on_stop(&self) {}

    /// Whether a batch in flight may be abandoned when the service stops, because the work only
    /// verifies and anything it leaves half done is found again by its next batch. A batch that
    /// is abandoned is dropped, which rolls back what it wrote through the batch. Batches run to
    /// their end unless the work says otherwise.
    fn interruptible(&self) -> bool {
        false
    }
}

/// How one attempt at a batch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// This replica led the batch and committed it.
    Committed,
    /// Another replica leads, or this one leads and the work is not due yet: the batch was
    /// skipped.
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
    wake: Option<Arc<Notify>>,
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
            wake: None,
        }
    }

    /// The same loop, which also starts its next batch as soon as `wake` is notified instead of
    /// waiting for the rest of the interval. A notification that arrives while a batch runs is
    /// kept for the next pause.
    #[must_use]
    pub fn with_wake(mut self, wake: Arc<Notify>) -> Self {
        self.wake = Some(wake);
        self
    }

    /// The name of the task, for the log entries of the supervisor.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.task.name()
    }

    /// How often the loop polls: the interval of its batches and of the retries of a replica
    /// without the lock.
    #[must_use]
    pub const fn interval(&self) -> SingletonInterval {
        self.interval
    }

    /// Tries one batch: leads and runs it when the lock is free, skips it otherwise.
    pub async fn run_batch(&self) -> BatchOutcome {
        match self.leadership.begin(&self.task).await {
            Ok(Leadership::Leader(batch)) => self.lead(batch).await,
            Ok(Leadership::Follower) => {
                self.work.on_follower().await;
                BatchOutcome::Skipped
            }
            Err(error) => {
                log_unavailable(self.task.name(), &error);
                BatchOutcome::Failed
            }
        }
    }

    /// Runs batches until the stop flag is set or its sender is gone. A batch in flight when the
    /// flag is set ends first, by a commit or a rollback, unless the work is
    /// [interruptible](SingletonWork::interruptible); the work then hears that the loop stopped. Every batch runs inside a
    /// `singleton.batch` span that names the task, so its log lines are told apart from those of a
    /// request.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        while !*shutdown.borrow() {
            if !self.batch_unless_stopped(&mut shutdown).await || !self.pause(&mut shutdown).await {
                break;
            }
        }
        self.stop_work().await;
    }

    /// Tells the work that the loop stopped, inside a `singleton.stop` span that names the task.
    async fn stop_work(&self) {
        let span = tracing::info_span!("singleton.stop", task = self.task.name());
        self.work.on_stop().instrument(span).await;
    }

    /// Runs one batch; `false` when the service stopped while an interruptible batch ran, which
    /// abandons that batch.
    async fn batch_unless_stopped(&self, shutdown: &mut watch::Receiver<bool>) -> bool {
        if !self.work.interruptible() {
            self.run_traced_batch().await;
            return true;
        }
        tokio::select! {
            _outcome = self.run_traced_batch() => true,
            stopping = shutdown.wait_for(|stopping| *stopping) => {
                drop(stopping);
                false
            }
        }
    }

    /// Runs one batch inside its `singleton.batch` span.
    async fn run_traced_batch(&self) -> BatchOutcome {
        let span = tracing::info_span!("singleton.batch", task = self.task.name());
        self.run_batch().instrument(span).await
    }

    /// Waits for the interval or the wake-up; `false` when the service is stopping instead.
    async fn pause(&self, shutdown: &mut watch::Receiver<bool>) -> bool {
        tokio::select! {
            () = tokio::time::sleep(self.interval.get()) => true,
            () = self.woken() => true,
            stopping = shutdown.wait_for(|stopping| *stopping) => {
                drop(stopping);
                false
            }
        }
    }

    /// Completes when the wake-up is notified; never when the loop has none.
    async fn woken(&self) {
        match &self.wake {
            Some(wake) => wake.notified().await,
            None => std::future::pending().await,
        }
    }

    async fn lead(&self, mut batch: Box<dyn LeaderBatch>) -> BatchOutcome {
        match self.work.is_due(self.clock.now()).await {
            Ok(true) => {}
            Ok(false) => {
                self.rollback(batch).await;
                return BatchOutcome::Skipped;
            }
            Err(error) => {
                log_rolled_back(self.task.name(), &error);
                return self.rollback(batch).await;
            }
        }
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
