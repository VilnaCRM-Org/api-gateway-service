//! Singleton leadership double of the IAM context.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{LeaderBatch, Leadership, RepositoryError, SingletonLeadership, SingletonTask};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the double does at one `begin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// This replica leads the batch.
    Lead,
    /// Another replica leads the batch.
    Follow,
    /// The storage is unavailable.
    Fail,
    /// This replica leads, but recording the run fails.
    LeadFailingRecord,
    /// This replica leads, but the commit fails.
    LeadFailingCommit,
}

/// What happened to the batches of the double, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A batch of the named task was opened (led or not).
    Begun(String),
    /// The led batch recorded a run at the time.
    Recorded(SystemTime),
    /// The led batch committed.
    Committed,
    /// The led batch rolled back.
    RolledBack,
}

/// A leadership that follows a script of steps, then repeats its default step.
#[derive(Debug)]
pub struct FakeSingletonLeadership {
    script: Mutex<VecDeque<Step>>,
    default: Step,
    events: Arc<Mutex<Vec<Event>>>,
}

/// A led batch of the double.
#[derive(Debug)]
struct FakeBatch {
    step: Step,
    events: Arc<Mutex<Vec<Event>>>,
}

fn down() -> RepositoryError {
    RepositoryError::Unavailable("the leadership storage is down".into())
}

impl FakeSingletonLeadership {
    /// A leadership that follows `script` and then takes `default` at every begin.
    #[must_use]
    pub fn new(script: &[Step], default: Step) -> Self {
        Self {
            script: Mutex::new(script.iter().copied().collect()),
            default,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A leadership that leads every batch.
    #[must_use]
    pub fn leading() -> Self {
        Self::new(&[], Step::Lead)
    }

    /// Everything that happened so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        locked(&self.events).clone()
    }

    fn next_step(&self) -> Step {
        locked(&self.script).pop_front().unwrap_or(self.default)
    }

    fn push(&self, event: Event) {
        locked(&self.events).push(event);
    }
}

#[async_trait]
impl SingletonLeadership for FakeSingletonLeadership {
    async fn begin(&self, task: &SingletonTask) -> Result<Leadership, RepositoryError> {
        self.push(Event::Begun(task.name().to_owned()));
        match self.next_step() {
            Step::Fail => Err(down()),
            Step::Follow => Ok(Leadership::Follower),
            step @ (Step::Lead | Step::LeadFailingRecord | Step::LeadFailingCommit) => {
                Ok(Leadership::Leader(Box::new(FakeBatch {
                    step,
                    events: Arc::clone(&self.events),
                })))
            }
        }
    }
}

#[async_trait]
impl LeaderBatch for FakeBatch {
    async fn record_run(&mut self, at: SystemTime) -> Result<(), RepositoryError> {
        if self.step == Step::LeadFailingRecord {
            return Err(down());
        }
        locked(&self.events).push(Event::Recorded(at));
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), RepositoryError> {
        if self.step == Step::LeadFailingCommit {
            return Err(down());
        }
        locked(&self.events).push(Event::Committed);
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), RepositoryError> {
        locked(&self.events).push(Event::RolledBack);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
