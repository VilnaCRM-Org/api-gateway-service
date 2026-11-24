//! Port of the leadership that fences a singleton task to one replica per batch (FR-45).

use std::time::SystemTime;

use crate::port::RepositoryError;

/// A task that exactly one replica runs per batch, named for its log entries and the row of
/// `iam_task_state`, with the constant that the advisory lock of the task is taken on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingletonTask {
    name: &'static str,
    lock_key: i64,
}

impl SingletonTask {
    /// A task named `name` whose batches are fenced by the lock `lock_key`; every task has its own
    /// key.
    #[must_use]
    pub const fn new(name: &'static str, lock_key: i64) -> Self {
        Self { name, lock_key }
    }

    /// The name of the task.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The constant that the lock of the task is taken on.
    #[must_use]
    pub const fn lock_key(&self) -> i64 {
        self.lock_key
    }
}

/// The row of `iam_task_state` that exists exactly while the state topic is ahead of PostgreSQL:
/// the anti-entropy task writes it in its batch, and the relay reads it in its own.
pub const TOPIC_AHEAD_STATE: &str = "anti-entropy.topic-ahead";

/// What the anti-entropy task left in the shared state for the relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TopicAheadState {
    /// Whether the last completed check found the topic ahead of PostgreSQL.
    pub held: bool,
    /// How many checks of the anti-entropy task completed (committed) so far.
    pub checks: u64,
}

/// One batch of a singleton task that this replica leads. Everything the batch writes belongs to
/// one transaction: dropping the batch, or a lost connection, rolls it back.
#[async_trait::async_trait]
pub trait LeaderBatch: std::fmt::Debug + Send {
    /// Records, inside the batch transaction, that the task ran at `at`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn record_run(&mut self, at: SystemTime) -> Result<(), RepositoryError>;

    /// Records, inside the batch transaction, that the check of the anti-entropy task found the
    /// state topic ahead of PostgreSQL (`held`) or not, at `at`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn write_topic_ahead(
        &mut self,
        held: bool,
        at: SystemTime,
    ) -> Result<(), RepositoryError>;

    /// Reads, inside the batch transaction, what the anti-entropy task left: whether it holds the
    /// relay back and how many checks of the task named `checker` completed.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn read_topic_ahead(&mut self, checker: &str)
    -> Result<TopicAheadState, RepositoryError>;

    /// Commits the batch and releases the leadership.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the commit fails; the batch is then rolled back.
    async fn commit(self: Box<Self>) -> Result<(), RepositoryError>;

    /// Rolls the batch back and releases the leadership.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails; the leadership ends with the
    /// transaction all the same.
    async fn rollback(self: Box<Self>) -> Result<(), RepositoryError>;
}

/// Whether this replica leads a batch.
#[derive(Debug)]
pub enum Leadership {
    /// No other replica runs a batch of the task: this one leads it.
    Leader(Box<dyn LeaderBatch>),
    /// Another replica leads the current batch; this one skips it.
    Follower,
}

/// Opens the batches of singleton tasks and decides which replica leads each.
#[async_trait::async_trait]
pub trait SingletonLeadership: std::fmt::Debug + Send + Sync {
    /// Opens the transaction of one batch of `task` and tries the lock of the task without
    /// waiting.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn begin(&self, task: &SingletonTask) -> Result<Leadership, RepositoryError>;
}

#[cfg(test)]
mod tests;
