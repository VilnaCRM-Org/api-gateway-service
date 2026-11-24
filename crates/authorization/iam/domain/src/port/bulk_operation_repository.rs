//! Repository port of the bulk operations (`iam_bulk_operations`).

use crate::bulk_operation::BulkOperation;
use crate::port::RepositoryError;
use crate::value_object::identifier::BulkOperationId;

/// Stores bulk operations and their progress.
#[async_trait::async_trait]
pub trait BulkOperationRepository: std::fmt::Debug + Send + Sync {
    /// Stores a new operation.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] for a known id and [`RepositoryError::Unavailable`]
    /// when the storage fails.
    async fn insert(&self, operation: &BulkOperation) -> Result<(), RepositoryError>;

    /// Stores the progress of a known operation.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] for an unknown id and [`RepositoryError::Unavailable`] when
    /// the storage fails.
    async fn save(&self, operation: &BulkOperation) -> Result<(), RepositoryError>;

    /// The operation with `id`, or `None`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find(&self, id: BulkOperationId) -> Result<Option<BulkOperation>, RepositoryError>;

    /// Up to `limit` operations in creation order (oldest first) that follow `after`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn list(
        &self,
        after: Option<BulkOperationId>,
        limit: u32,
    ) -> Result<Vec<BulkOperation>, RepositoryError>;

    /// The oldest operation that is neither completed nor failed, or `None`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn oldest_unfinished(&self) -> Result<Option<BulkOperation>, RepositoryError>;
}
