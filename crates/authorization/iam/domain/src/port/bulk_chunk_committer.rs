//! Port that commits the next chunk of a bulk operation.

use shared_domain::BoxError;

use crate::bulk_operation::{BulkOperation, BulkStamp};
use crate::value_object::policy_version::PolicyVersion;

/// One committed chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedChunk {
    /// How many records the chunk applied.
    pub records: u64,
    /// The policy version that the chunk took.
    pub version: PolicyVersion,
}

/// A chunk that was not committed.
#[derive(Debug, thiserror::Error)]
pub enum ChunkCommitError {
    /// The change can never be applied (for example the plan is gone or a rule refuses it): the
    /// operation fails with the reason and is not retried.
    #[error("the bulk operation cannot be applied: {0}")]
    Permanent(String),
    /// The storage failed; nothing was committed and the chunk is tried again later.
    #[error("the chunk could not be committed")]
    Unavailable(#[source] BoxError),
}

/// Commits the next chunk of a bulk operation as one versioned change.
///
/// The commit writes the chunk, the progress of the operation (through
/// [`BulkOperation::record_chunk`]) and, for the last chunk, the envelope of the completion event
/// in one transaction, so a chunk is never applied twice and a restart resumes from the applied
/// records.
#[async_trait::async_trait]
pub trait BulkChunkCommitter: std::fmt::Debug + Send + Sync {
    /// Commits the chunk that follows the applied records of `operation`.
    ///
    /// # Errors
    ///
    /// [`ChunkCommitError::Permanent`] when the change cannot be applied and
    /// [`ChunkCommitError::Unavailable`] when the storage fails.
    async fn commit_next_chunk(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError>;
}
