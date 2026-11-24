//! Hands each bulk operation to the chunk committer of its kind (FR-84).

use std::sync::Arc;

use iam_domain::{
    BulkChunkCommitter, BulkKind, BulkOperation, BulkStamp, ChunkCommitError, CommittedChunk,
};

/// Commits the chunks of every kind of bulk operation that has a committer.
///
/// A role deletion and a resync have one. An operation of another kind has no committer, so it
/// fails with the reason instead of waiting for ever at the head of the queue.
#[derive(Debug)]
pub struct BulkChunkRouter {
    role_deletion: Arc<dyn BulkChunkCommitter>,
    resync: Arc<dyn BulkChunkCommitter>,
}

impl BulkChunkRouter {
    /// A router over the committer of the role deletions and the one of the resyncs.
    #[must_use]
    pub fn new(
        role_deletion: Arc<dyn BulkChunkCommitter>,
        resync: Arc<dyn BulkChunkCommitter>,
    ) -> Self {
        Self {
            role_deletion,
            resync,
        }
    }

    /// Commits the next chunk of `operation` through the committer of its kind.
    async fn route(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        let kind = operation.parts().kind;
        match self.committer_of(kind) {
            Some(committer) => committer.commit_next_chunk(operation, stamp).await,
            None => Err(ChunkCommitError::Permanent(format!(
                "no committer handles bulk operations of kind {}",
                kind.as_str()
            ))),
        }
    }

    /// The committer of `kind`, if the kind has one.
    fn committer_of(&self, kind: BulkKind) -> Option<&Arc<dyn BulkChunkCommitter>> {
        match kind {
            BulkKind::RoleDeletion => Some(&self.role_deletion),
            BulkKind::Resync => Some(&self.resync),
            BulkKind::Catalogue | BulkKind::Other => None,
        }
    }
}

#[async_trait::async_trait]
impl BulkChunkCommitter for BulkChunkRouter {
    async fn commit_next_chunk(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        self.route(operation, stamp).await
    }
}

#[cfg(test)]
mod tests;
