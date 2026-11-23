//! Repository port of the state that singleton tasks keep (`iam_task_state`).

use std::time::SystemTime;

use crate::port::RepositoryError;

/// What the last committed batch of a singleton task recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskState {
    /// When the last committed batch ran.
    pub last_run_at: SystemTime,
    /// How many batches committed.
    pub run_count: u64,
}

/// Reads the state of singleton tasks.
#[async_trait::async_trait]
pub trait TaskStateRepository: std::fmt::Debug + Send + Sync {
    /// The state of the task `name`, or `None` when no batch of it ever committed.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find(&self, name: &str) -> Result<Option<TaskState>, RepositoryError>;
}
