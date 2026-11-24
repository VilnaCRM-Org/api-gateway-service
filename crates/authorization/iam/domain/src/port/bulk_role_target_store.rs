//! Port that remembers which role a role-deletion bulk operation deletes.

use crate::port::RepositoryError;
use crate::value_object::identifier::{BulkOperationId, RoleId};

/// Stores the role that a bulk operation of kind `role_deletion` deletes, so that the runner can
/// commit the chunks of the deletion after the request that recorded it has ended.
#[async_trait::async_trait]
pub trait BulkRoleTargetStore: std::fmt::Debug + Send + Sync {
    /// Remembers that `operation` deletes `role`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when the operation already has a target and
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn insert(&self, operation: BulkOperationId, role: RoleId)
    -> Result<(), RepositoryError>;

    /// The role that `operation` deletes, or `None` when no target is stored.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find(&self, operation: BulkOperationId) -> Result<Option<RoleId>, RepositoryError>;
}
