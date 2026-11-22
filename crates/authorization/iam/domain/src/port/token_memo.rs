//! Memo port of token resolutions.

use crate::value_object::credential_digest::CredentialDigest;
use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

/// The verification a memo runs on a miss: the verifier applied to the credential of the digest.
pub type Verification<'a> = &'a (dyn Fn() -> Result<TokenIdentity, TokenRejection> + Send + Sync);

/// A per-process memo of token resolutions keyed by credential digest: a positive memo of
/// identities and a separately bounded negative memo of rejections.
#[async_trait::async_trait]
pub trait TokenMemo: std::fmt::Debug + Send + Sync {
    /// The rejection memoized for `digest`, while its negative entry lives.
    async fn rejection(&self, digest: &CredentialDigest) -> Option<TokenRejection>;

    /// The identity memoized for `digest`, while its positive entry lives; on a miss runs `verify`
    /// once for every concurrent caller of the same digest and memoizes its outcome, an identity
    /// in the positive memo and a rejection in the negative memo.
    ///
    /// # Errors
    ///
    /// Returns the rejection of `verify`.
    async fn resolve(
        &self,
        digest: &CredentialDigest,
        verify: Verification<'_>,
    ) -> Result<TokenIdentity, TokenRejection>;

    /// Drops every entry of both memos, for example when the trusted key set changed.
    async fn flush(&self);
}
