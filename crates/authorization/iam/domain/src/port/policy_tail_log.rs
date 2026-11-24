//! Port that follows the state topic in tail mode (FR-71, FR-72): the gateway keeps its position
//! in memory and asks for the records after it.
//!
//! The reader hands back raw framed batches with the broker append time of every record and the
//! bounds of the partition, so that the pure tail step can judge an out-of-range position, a
//! watermark that moved backwards and a record that is too old, without any I/O of its own.

use crate::port::policy_bootstrap_log::FramedRecord;
use crate::port::policy_log_tail::PolicyLogTailError;

/// One framed record with the time the broker appended it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedRecord {
    /// The record with its offset and framing.
    pub framed: FramedRecord,
    /// The broker append time in milliseconds since the epoch; `None` when the topic stamps the
    /// producer's create time instead, which no append-time check can use.
    pub appended_at_ms: Option<i64>,
}

/// What one poll of the tail returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailBatch {
    /// The records at or after the polled position, in offset order, at most
    /// [`TAIL_READ_LIMIT`](super::policy_log_tail::TAIL_READ_LIMIT) of them.
    pub records: Vec<TimedRecord>,
    /// The first offset the partition still holds.
    pub low: i64,
    /// The offset after the last record a `read_committed` reader can see.
    pub high: i64,
}

/// Follows the committed records of the state topic from a position kept by the caller.
#[async_trait::async_trait]
pub trait PolicyTailLog: std::fmt::Debug + Send + Sync {
    /// Waits for the records at or after `position` for at most the configured fetch wait. An
    /// empty batch is an idle tail. The reader reseeks to `position` whenever it is not already
    /// there, which is how a reconnect or a watermark that moved while the tail was idle recovers.
    ///
    /// # Errors
    ///
    /// [`PolicyLogTailError::Unavailable`] when the cluster does not answer and
    /// [`PolicyLogTailError::Malformed`] for a record that is not a record of this service.
    async fn poll(&self, position: i64) -> Result<TailBatch, PolicyLogTailError>;

    /// Releases the connection, so nothing stays open when the tail stops.
    async fn close(&self);
}
