//! A buffer of refused requests for the tests of the use cases that offer or drain them.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use iam_domain::{AttemptSummary, RejectedAttempt, RejectedAttemptBuffer, RejectedAttemptLog};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The domain buffer behind the port, remembering every attempt that was offered.
#[derive(Debug, Default)]
pub(crate) struct FakeRejectedAttemptLog {
    buffer: Mutex<RejectedAttemptBuffer>,
    offered: Mutex<Vec<RejectedAttempt>>,
}

impl FakeRejectedAttemptLog {
    /// An empty buffer.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Every attempt offered so far, in order.
    pub(crate) fn offered(&self) -> Vec<RejectedAttempt> {
        locked(&self.offered).clone()
    }
}

impl RejectedAttemptLog for FakeRejectedAttemptLog {
    fn offer(&self, attempt: RejectedAttempt) {
        locked(&self.offered).push(attempt.clone());
        locked(&self.buffer).offer(attempt);
    }

    fn drain(&self, now: SystemTime) -> Vec<AttemptSummary> {
        locked(&self.buffer).drain(now)
    }

    fn requeue(&self, summaries: Vec<AttemptSummary>) {
        locked(&self.buffer).requeue(summaries);
    }
}
