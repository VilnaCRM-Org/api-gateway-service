//! Propagation store double: the stored offsets of the `__head` rows and the recorded outcomes.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{ChangeId, PolicyVersion, PropagationOutcome, PropagationStore, RepositoryError};

/// The state of the double.
#[derive(Debug, Default)]
struct State {
    offsets: HashMap<i64, i64>,
    recorded: Vec<(ChangeId, PropagationOutcome)>,
    polls: usize,
}

/// A propagation store that answers from memory.
#[derive(Debug, Default)]
pub struct FakePropagationStore {
    state: Mutex<State>,
    failing: bool,
}

impl FakePropagationStore {
    /// A store without stored offsets: no version is published.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that answers `Unavailable` to every call.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            state: Mutex::new(State::default()),
            failing: true,
        }
    }

    /// A store where `version` is published at `offset`.
    #[must_use]
    pub fn publishing(version: i64, offset: i64) -> Self {
        let store = Self::new();
        store.publish(version, offset);
        store
    }

    /// Stores the acknowledgement of the `__head` row of `version` at `offset`.
    pub fn publish(&self, version: i64, offset: i64) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .offsets
            .insert(version, offset);
    }

    /// The outcomes recorded so far, oldest first.
    #[must_use]
    pub fn recorded(&self) -> Vec<(ChangeId, PropagationOutcome)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recorded
            .clone()
    }

    /// How many times the offset of a version was asked for.
    #[must_use]
    pub fn polls(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .polls
    }
}

#[async_trait]
impl PropagationStore for FakePropagationStore {
    async fn published_head_offset(
        &self,
        version: PolicyVersion,
    ) -> Result<Option<i64>, RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable(
                "in-memory store failure".into(),
            ));
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.polls = state.polls.saturating_add(1);
        Ok(state.offsets.get(&version.value()).copied())
    }

    async fn record(
        &self,
        change_id: ChangeId,
        outcome: PropagationOutcome,
    ) -> Result<(), RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable(
                "in-memory store failure".into(),
            ));
        }
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recorded
            .push((change_id, outcome));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
