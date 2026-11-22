//! Token resolution port (board name `TokenRepository`).

use crate::value_object::credential::Credential;
use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

/// Resolves a bearer credential to the identity it proves, on every request: memoized
/// verification followed by the revocation check. Tokens are never persisted.
#[async_trait::async_trait]
pub trait TokenRepository: std::fmt::Debug + Send + Sync {
    /// The identity of a valid, unrevoked credential.
    ///
    /// # Errors
    ///
    /// Returns the [`TokenRejection`] of the verifier, [`TokenRejection::Revoked`] when the
    /// revocation state refuses the token and [`TokenRejection::Unavailable`] when the revocation
    /// state cannot be read.
    async fn resolve(&self, credential: &Credential) -> Result<TokenIdentity, TokenRejection>;
}
