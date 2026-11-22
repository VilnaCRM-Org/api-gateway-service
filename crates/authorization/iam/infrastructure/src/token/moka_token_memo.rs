//! [`TokenMemo`] backed by two bounded `moka` caches.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{CredentialDigest, TokenIdentity, TokenMemo, TokenRejection, Verification};
use shared_domain::Clock;

/// The size and lifetime of the positive memo (`TOKEN_MEMO_CAPACITY`, `TOKEN_MEMO_MAX_TTL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenMemoSettings {
    /// The largest number of memoized identities.
    pub capacity: u64,
    /// The longest time an identity is memoized.
    pub max_ttl: Duration,
}

/// A memoized identity and the instant of the `Clock` port at which it stops being served.
#[derive(Debug, Clone)]
struct Memoized {
    identity: TokenIdentity,
    until: SystemTime,
}

/// A memoized rejection and the instant at which it stops being served.
#[derive(Debug, Clone, Copy)]
struct Rejected {
    rejection: TokenRejection,
    until: SystemTime,
}

/// A positive memo of identities and a separately bounded negative memo of rejections.
///
/// Identities live `min(exp − now, TOKEN_MEMO_MAX_TTL)` within the capacity
/// `TOKEN_MEMO_CAPACITY`; the negative memo holds [`Self::NEGATIVE_CAPACITY`]
/// rejections for [`Self::NEGATIVE_TTL`], so that a flood of invalid tokens never evicts a valid
/// entry. Lifetimes are measured on the `Clock` port; keys are credential digests only.
pub struct MokaTokenMemo {
    positive: moka::future::Cache<CredentialDigest, Memoized>,
    negative: moka::future::Cache<CredentialDigest, Rejected>,
    max_ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl MokaTokenMemo {
    /// The largest number of memoized rejections.
    pub const NEGATIVE_CAPACITY: u64 = 10_000;

    /// How long a rejection is memoized.
    pub const NEGATIVE_TTL: Duration = Duration::from_secs(5);

    /// Two empty memos.
    #[must_use]
    pub fn new(settings: TokenMemoSettings, clock: Arc<dyn Clock>) -> Self {
        let positive = moka::future::Cache::builder()
            .max_capacity(settings.capacity)
            .time_to_live(settings.max_ttl)
            .build();
        let negative = moka::future::Cache::builder()
            .max_capacity(Self::NEGATIVE_CAPACITY)
            .time_to_live(Self::NEGATIVE_TTL)
            .build();
        Self {
            positive,
            negative,
            max_ttl: settings.max_ttl,
            clock,
        }
    }

    async fn memoized_rejection(&self, digest: &CredentialDigest) -> Option<TokenRejection> {
        let now = self.clock.now();
        self.negative
            .get(digest)
            .await
            .filter(|entry| entry.until > now)
            .map(|entry| entry.rejection)
    }

    async fn resolve_identity(
        &self,
        digest: &CredentialDigest,
        verify: Verification<'_>,
    ) -> Result<TokenIdentity, TokenRejection> {
        if let Some(identity) = self.live_identity(digest).await {
            return Ok(identity);
        }
        match self
            .positive
            .try_get_with(*digest, async { self.verified(verify) })
            .await
        {
            Ok(entry) => {
                self.drop_when_expired(digest, &entry).await;
                Ok(entry.identity)
            }
            Err(rejection) => {
                let rejection = *rejection;
                self.remember_rejection(digest, rejection).await;
                Err(rejection)
            }
        }
    }

    /// The memoized identity of `digest` while it lives; an expired entry is dropped.
    async fn live_identity(&self, digest: &CredentialDigest) -> Option<TokenIdentity> {
        let entry = self.positive.get(digest).await?;
        if entry.until > self.clock.now() {
            return Some(entry.identity);
        }
        self.positive.invalidate(digest).await;
        None
    }

    /// Drops the entry of `digest` when it no longer lives, so it is never served.
    async fn drop_when_expired(&self, digest: &CredentialDigest, entry: &Memoized) {
        if entry.until <= self.clock.now() {
            self.positive.invalidate(digest).await;
        }
    }

    /// Runs the verification and computes the instant until which its identity is served.
    fn verified(&self, verify: Verification<'_>) -> Result<Memoized, TokenRejection> {
        let identity = verify()?;
        let expires_at = identity.expires_at();
        let until = self
            .clock
            .now()
            .checked_add(self.max_ttl)
            .map_or(expires_at, |limit| limit.min(expires_at));
        Ok(Memoized { identity, until })
    }

    async fn remember_rejection(&self, digest: &CredentialDigest, rejection: TokenRejection) {
        let now = self.clock.now();
        let until = now.checked_add(Self::NEGATIVE_TTL).unwrap_or(now);
        self.negative
            .insert(*digest, Rejected { rejection, until })
            .await;
    }

    fn flush_all(&self) {
        self.positive.invalidate_all();
        self.negative.invalidate_all();
    }
}

impl std::fmt::Debug for MokaTokenMemo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MokaTokenMemo")
            .field("positive", &self.positive.entry_count())
            .field("negative", &self.negative.entry_count())
            .field("max_ttl", &self.max_ttl)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl TokenMemo for MokaTokenMemo {
    async fn rejection(&self, digest: &CredentialDigest) -> Option<TokenRejection> {
        self.memoized_rejection(digest).await
    }

    async fn resolve(
        &self,
        digest: &CredentialDigest,
        verify: Verification<'_>,
    ) -> Result<TokenIdentity, TokenRejection> {
        self.resolve_identity(digest, verify).await
    }

    async fn flush(&self) {
        self.flush_all();
    }
}

#[cfg(test)]
mod tests;
