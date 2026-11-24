//! Port that reads the state topic back with bounded reads (FR-77): a range of records up to a
//! watermark, and the record at one offset.
//!
//! The first form serves the anti-entropy task of `iam-control`; Story 9.3 adds the bootstrap
//! principal, the tail mode and the reseek of the gateway to the adapter.

use shared_domain::BoxError;

use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// The most records that one [`PolicyLogTail::read_range`] returns.
pub const TAIL_READ_LIMIT: usize = 500;

/// One record of the state topic as the reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailRecord {
    /// The offset of the record in the partition.
    pub offset: i64,
    /// The record key, the printed form of a state key.
    pub key: String,
    /// The value; `None` is a tombstone.
    pub payload: Option<String>,
    /// The policy version of the record (`iam-version`).
    pub version: PolicyVersion,
    /// The epoch of the relay that appended the record (`iam-relay-epoch`).
    pub relay_epoch: RelayEpoch,
}

/// The topic could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PolicyLogTailError {
    /// The cluster cannot be reached or answered with a failure; the read is to be repeated.
    #[error("the state topic cannot be read")]
    Unavailable(#[source] BoxError),
    /// The record at `offset` has no key, an unreadable value or a missing or invalid framing
    /// header, which no writer of this service produces.
    #[error("the record at offset {offset} of the state topic is malformed")]
    Malformed {
        /// The offset of the record.
        offset: i64,
    },
}

/// Reads the committed records of the state topic.
#[async_trait::async_trait]
pub trait PolicyLogTail: std::fmt::Debug + Send + Sync {
    /// The watermark: the offset after the last record a `read_committed` reader can see.
    ///
    /// # Errors
    ///
    /// [`PolicyLogTailError::Unavailable`] when the cluster does not answer.
    async fn watermark(&self) -> Result<i64, PolicyLogTailError>;

    /// The records with `from <= offset < up_to` that exist, in offset order and at most
    /// [`TAIL_READ_LIMIT`] of them; an offset that holds no record (compacted away, or a
    /// transaction marker) is left out. A caller that wants more continues after the last offset
    /// it received. `up_to` beyond the watermark ends at the watermark.
    ///
    /// # Errors
    ///
    /// [`PolicyLogTailError::Unavailable`] when the cluster does not answer and
    /// [`PolicyLogTailError::Malformed`] for a record that is not a record of this service.
    async fn read_range(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<TailRecord>, PolicyLogTailError>;

    /// The record stored exactly at `offset`; `None` when the offset holds none.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::read_range`].
    async fn read_at(&self, offset: i64) -> Result<Option<TailRecord>, PolicyLogTailError>;

    /// Releases the connection the reader holds, so nothing stays open when its task stops; the
    /// next read opens a new one.
    async fn close(&self);
}
