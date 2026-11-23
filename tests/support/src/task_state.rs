//! Task state repository double of the IAM context.

use std::collections::BTreeMap;

use async_trait::async_trait;
use iam_domain::{RepositoryError, TaskState, TaskStateRepository};

/// A task state repository that answers from memory.
#[derive(Debug, Default)]
pub struct FakeTaskStateRepository {
    states: BTreeMap<String, TaskState>,
    failing: bool,
}

impl FakeTaskStateRepository {
    /// A repository in which no task ever ran.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            failing: false,
        }
    }

    /// The same repository in which the task `name` has `state`.
    #[must_use]
    pub fn with_state(mut self, name: &str, state: TaskState) -> Self {
        self.states.insert(name.to_owned(), state);
        self
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            states: BTreeMap::new(),
            failing: true,
        }
    }
}

#[async_trait]
impl TaskStateRepository for FakeTaskStateRepository {
    async fn find(&self, name: &str) -> Result<Option<TaskState>, RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable(
                "in-memory task state failure".into(),
            ));
        }
        Ok(self.states.get(name).copied())
    }
}

#[cfg(test)]
mod tests;
