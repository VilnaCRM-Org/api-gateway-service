//! Port that lists every entity of the policy, so that a resync can publish them all (FR-78).

use crate::port::RepositoryError;
use crate::resync::InventoryEntry;

/// Lists the entities of the policy that the system of record holds.
///
/// The order is stable: the roles, the subjects, the upstreams, the routes, the rate policies and
/// the catalogues of the services, each kind in the order of its key.
#[async_trait::async_trait]
pub trait PolicyStateInventory: std::fmt::Debug + Send + Sync {
    /// The number of entries: one per entity that has a state record.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn count(&self) -> Result<u64, RepositoryError>;

    /// Up to `limit` entries that follow the first `offset` entries of the stable order.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn page(&self, offset: u64, limit: u64) -> Result<Vec<InventoryEntry>, RepositoryError>;
}
