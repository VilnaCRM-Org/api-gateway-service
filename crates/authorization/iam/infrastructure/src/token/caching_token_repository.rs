//! [`TokenRepository`] that memoizes verifications and checks revocations on every call.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use iam_domain::{
    AccessTokenVerifier, Credential, CredentialDigest, RevocationRule, RevocationView,
    TokenIdentity, TokenMemo, TokenRejection, TokenRepository,
};
use sha2::{Digest as _, Sha256};

/// The single owner of the token memos.
///
/// It digests the credential with SHA-256, consults the negative and positive memos, verifies on
/// a miss and checks the [`RevocationView`] on every call, memo hits included. Both memos are
/// flushed when the verifier's key set changes.
#[derive(Debug)]
pub struct CachingTokenRepository {
    verifier: Arc<dyn AccessTokenVerifier>,
    memo: Arc<dyn TokenMemo>,
    revocations: Arc<dyn RevocationView>,
    key_set_version: AtomicU64,
}

impl CachingTokenRepository {
    /// Composes the verifier, the memo and the revocation view.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn AccessTokenVerifier>,
        memo: Arc<dyn TokenMemo>,
        revocations: Arc<dyn RevocationView>,
    ) -> Self {
        let key_set_version = AtomicU64::new(verifier.key_set_version());
        Self {
            verifier,
            memo,
            revocations,
            key_set_version,
        }
    }

    /// Resolves `credential` like [`TokenRepository::resolve`], reading the revocation state from
    /// `revocations` instead of the view this repository was built with.
    ///
    /// The gateway passes a view over the snapshot that the request loaded, so the revocation check
    /// reads the same version as the decision that follows; the memos stay shared.
    ///
    /// # Errors
    ///
    /// The same rejections as [`TokenRepository::resolve`].
    pub async fn resolve_with(
        &self,
        revocations: &dyn RevocationView,
        credential: &Credential,
    ) -> Result<TokenIdentity, TokenRejection> {
        self.resolve_credential(revocations, credential).await
    }

    async fn resolve_credential(
        &self,
        revocations: &dyn RevocationView,
        credential: &Credential,
    ) -> Result<TokenIdentity, TokenRejection> {
        if credential.is_blank() {
            return Err(TokenRejection::Missing);
        }
        self.flush_when_the_key_set_changed().await;
        let identity = self.memoized_identity(credential).await?;
        Self::check_revocation(revocations, &identity).await?;
        Ok(identity)
    }

    /// The identity from the memos, verified on a miss.
    async fn memoized_identity(
        &self,
        credential: &Credential,
    ) -> Result<TokenIdentity, TokenRejection> {
        let digest = logged_digest(credential);
        if let Some(rejection) = self.memo.rejection(&digest).await {
            return Err(rejection);
        }
        let verify = || {
            self.verifier
                .verify(credential)
                .map(|token| TokenIdentity::from(&token))
        };
        self.memo.resolve(&digest, &verify).await
    }

    /// Applies the [`RevocationRule`] to the current revocation state.
    async fn check_revocation(
        revocations: &dyn RevocationView,
        identity: &TokenIdentity,
    ) -> Result<(), TokenRejection> {
        let status = revocations.status(identity).await.map_err(|error| {
            tracing::warn!(error = %error, "the revocation state cannot be read");
            TokenRejection::Unavailable
        })?;
        RevocationRule::check(identity, &status)
    }

    async fn flush_when_the_key_set_changed(&self) {
        let current = self.verifier.key_set_version();
        if self.key_set_version.swap(current, Ordering::AcqRel) != current {
            self.memo.flush().await;
        }
    }
}

/// The digest of the credential, logged in place of the credential.
fn logged_digest(credential: &Credential) -> CredentialDigest {
    let digest = digest(credential);
    tracing::debug!(credential = ?digest, "resolving an access token");
    digest
}

/// The SHA-256 digest of the raw credential, the only form a memo key holds.
#[must_use]
pub fn digest(credential: &Credential) -> CredentialDigest {
    CredentialDigest::new(Sha256::digest(credential.expose().as_bytes()).into())
}

#[async_trait::async_trait]
impl TokenRepository for CachingTokenRepository {
    async fn resolve(&self, credential: &Credential) -> Result<TokenIdentity, TokenRejection> {
        self.resolve_credential(self.revocations.as_ref(), credential)
            .await
    }
}

#[cfg(test)]
mod tests;
