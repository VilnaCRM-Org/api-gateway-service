//! Port that writes access records.

use crate::access_log::{AccessEntry, AccessLane};

/// Writes the entries of the access log, one lane at a time.
///
/// The sink runs on the dedicated writer thread, never on a request task, so a write may block.
/// It reports no error: the access log is best effort, and a sink that cannot write counts and
/// logs the loss itself.
pub trait AccessLogSink: std::fmt::Debug + Send + Sync {
    /// Writes `entry` to `lane`.
    fn write(&self, lane: AccessLane, entry: &AccessEntry);

    /// How many entries of the audit lane the log store has acknowledged since the sink started,
    /// or `None` for a sink that keeps no such account, whose audit entries count as acknowledged
    /// when they are written (Story 14.2, FR-50).
    ///
    /// The count only grows, and entries are acknowledged in the order they were written.
    fn acknowledged_audit(&self) -> Option<u64> {
        None
    }

    /// Pushes what the sink still holds and waits for the answer; called once, when the writer
    /// stops.
    fn flush(&self) {}
}
