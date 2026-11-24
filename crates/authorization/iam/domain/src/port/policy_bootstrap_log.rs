//! Port that reads the state topic for the bootstrap of a gateway pod (FR-71, FR-77): the last
//! stable offset, and the framed records of a range, read under the bootstrap principal.
//!
//! The reads of [`PolicyLogTail`](super::policy_log_tail::PolicyLogTail) return the key, the
//! value, the version and the relay epoch. The bootstrap also needs the sequence, the count, the
//! digest after the record and the log epoch, so it reads through this port.

use crate::port::policy_log_tail::PolicyLogTailError;
use crate::snapshot::assembly::VersionedRecord;

/// One record of the state topic with its offset and the whole framing of its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedRecord {
    /// The offset of the record in the partition.
    pub offset: i64,
    /// The record with its framing.
    pub record: VersionedRecord,
}

/// Reads the committed records of the state topic from offset 0.
#[async_trait::async_trait]
pub trait PolicyBootstrapLog: std::fmt::Debug + Send + Sync {
    /// The last stable offset: the offset after the last record a `read_committed` reader can
    /// see, from `ListOffsets` with isolation `READ_COMMITTED`.
    ///
    /// # Errors
    ///
    /// [`PolicyLogTailError::Unavailable`] when the cluster does not answer.
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError>;

    /// The framed records with `from <= offset < up_to` that exist, in offset order, at most
    /// [`TAIL_READ_LIMIT`](super::policy_log_tail::TAIL_READ_LIMIT) of them; the caller continues
    /// after the last offset it received. `up_to` beyond the stable end ends at the stable end.
    ///
    /// # Errors
    ///
    /// [`PolicyLogTailError::Unavailable`] when the cluster does not answer and
    /// [`PolicyLogTailError::Malformed`] for a record that is not a record of this service.
    async fn read_framed(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<FramedRecord>, PolicyLogTailError>;

    /// Releases the connection, so nothing stays open when the bootstrap ends.
    async fn close(&self);
}
