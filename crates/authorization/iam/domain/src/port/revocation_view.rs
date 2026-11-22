//! Read port of the revocation state.

use crate::port::RepositoryError;
use crate::revocation::revocation_rule::RevocationStatus;
use crate::value_object::token_identity::TokenIdentity;

/// Reads the revocation state that applies to a token: the policy snapshot at the gateway,
/// PostgreSQL in `iam-control`.
#[async_trait::async_trait]
pub trait RevocationView: std::fmt::Debug + Send + Sync {
    /// Whether the token's session is revoked, the cut-off of its user (none for a service
    /// principal) and the global cut-off.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the state cannot be read.
    async fn status(&self, identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError>;
}
