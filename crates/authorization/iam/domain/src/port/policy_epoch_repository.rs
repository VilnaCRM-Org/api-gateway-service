//! Repository port of the policy epoch.

use crate::port::RepositoryError;
use crate::value_object::policy_epoch::PolicyEpoch;

/// Reads the single policy epoch row of the system of record.
#[async_trait::async_trait]
pub trait PolicyEpochRepository: std::fmt::Debug + Send + Sync {
    /// Returns the current policy epoch.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when the row is missing, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn current(&self) -> Result<PolicyEpoch, RepositoryError>;
}
