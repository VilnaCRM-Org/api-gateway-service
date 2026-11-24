//! Port of the buffer that holds refused requests until they are appended to the audit log.

use std::time::SystemTime;

use crate::rejected_attempt::{AttemptSummary, RejectedAttempt};

/// Holds the refusals of IAM's operations between the request and the append to the audit chain.
///
/// Offering never waits for the storage, so a refusal never waits for the chain-head lock.
pub trait RejectedAttemptLog: std::fmt::Debug + Send + Sync {
    /// Offers one refusal; it returns at once.
    fn offer(&self, attempt: RejectedAttempt);

    /// Takes the summaries that are due at `now`.
    fn drain(&self, now: SystemTime) -> Vec<AttemptSummary>;

    /// Gives back summaries that could not be appended, so that the next drain returns them.
    fn requeue(&self, summaries: Vec<AttemptSummary>);
}
