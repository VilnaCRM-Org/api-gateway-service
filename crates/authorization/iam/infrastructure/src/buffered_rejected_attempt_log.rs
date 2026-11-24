//! [`RejectedAttemptLog`] that keeps the refusals in memory until the writer appends them.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use iam_domain::{AttemptSummary, RejectedAttempt, RejectedAttemptBuffer, RejectedAttemptLog};

/// The per-replica buffer of refused requests (FR-49).
///
/// Offering takes a lock held for a map update only, never across an await or a storage call, so a
/// refusal never waits for the chain-head lock of the audit log. Identical refusals of one actor
/// within 60 seconds are summarised into one record with a count.
#[derive(Debug, Default)]
pub struct BufferedRejectedAttemptLog {
    buffer: Mutex<RejectedAttemptBuffer>,
}

impl BufferedRejectedAttemptLog {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The buffer; a panic of another holder cannot leave it half updated, so a poisoned lock is
    /// used as it is.
    fn locked(&self) -> MutexGuard<'_, RejectedAttemptBuffer> {
        self.buffer.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl RejectedAttemptLog for BufferedRejectedAttemptLog {
    fn offer(&self, attempt: RejectedAttempt) {
        self.locked().offer(attempt);
    }

    fn drain(&self, now: SystemTime) -> Vec<AttemptSummary> {
        self.locked().drain(now)
    }

    fn requeue(&self, summaries: Vec<AttemptSummary>) {
        self.locked().requeue(summaries);
    }
}

#[cfg(test)]
mod tests;
