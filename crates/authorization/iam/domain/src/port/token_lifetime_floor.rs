//! Port of the longest `MAX_TOKEN_LIFETIME` that was ever configured.

use std::time::Duration;

use crate::port::RepositoryError;

/// Keeps the longest token lifetime ever configured, which sizes how long a revocation record
/// must stay: a token issued under a longer lifetime may still be alive after the configured one
/// was lowered.
#[async_trait::async_trait]
pub trait TokenLifetimeFloor: std::fmt::Debug + Send + Sync {
    /// Raises the stored floor to `configured` when `configured` is higher, and returns the
    /// floor after the call. A lower value never lowers the floor.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn raise_to(&self, configured: Duration) -> Result<Duration, RepositoryError>;

    /// The stored floor, or `None` when no value was ever stored.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn longest(&self) -> Result<Option<Duration>, RepositoryError>;
}
