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
}
