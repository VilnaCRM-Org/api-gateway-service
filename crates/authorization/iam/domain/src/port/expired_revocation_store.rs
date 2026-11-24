//! Port that finds the revocation records whose prune-after instant has passed.

use std::time::SystemTime;

use crate::port::RepositoryError;
use crate::revocation::expired_revocation::ExpiredRevocation;

/// Reads the revocation records that may be tombstoned.
///
/// The records leave through the [`IamUnitOfWork`](crate::IamUnitOfWork), as a change with a prune
/// statement and an audit record for each; this port only finds them.
#[async_trait::async_trait]
pub trait ExpiredRevocationStore: std::fmt::Debug + Send + Sync {
    /// At most `limit` session revocations and user cut-offs whose `prune_after` is strictly before
    /// `now`, oldest first. The global cut-off is never one of them.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn expired_revocations(
        &self,
        now: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredRevocation>, RepositoryError>;
}
