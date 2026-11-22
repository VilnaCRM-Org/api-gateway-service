//! Token memo and token repository doubles of the IAM context.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    Credential, CredentialDigest, TokenIdentity, TokenMemo, TokenRejection, TokenRepository,
    Verification,
};

/// The memoized outcomes, keyed by the digest bytes.
#[derive(Debug, Default)]
struct Memos {
    positive: BTreeMap<[u8; CredentialDigest::LENGTH], TokenIdentity>,
    negative: BTreeMap<[u8; CredentialDigest::LENGTH], TokenRejection>,
}

/// A token memo without lifetimes or capacity: it keeps every outcome until it is flushed, and
/// counts the verifications it ran and the flushes.
#[derive(Debug, Default)]
pub struct FakeTokenMemo {
    memos: Mutex<Memos>,
    verifications: AtomicUsize,
    flushes: AtomicUsize,
}

impl FakeTokenMemo {
    /// An empty memo.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many verifications the memo ran on a miss.
    #[must_use]
    pub fn verifications(&self) -> usize {
        self.verifications.load(Ordering::Acquire)
    }

    /// How many times the memo was flushed.
    #[must_use]
    pub fn flushes(&self) -> usize {
        self.flushes.load(Ordering::Acquire)
    }

    /// How many identities and rejections are memoized.
    #[must_use]
    pub fn entries(&self) -> (usize, usize) {
        let memos = self.memos.lock().unwrap_or_else(PoisonError::into_inner);
        (memos.positive.len(), memos.negative.len())
    }

    fn memos(&self) -> std::sync::MutexGuard<'_, Memos> {
        self.memos.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl TokenMemo for FakeTokenMemo {
    async fn rejection(&self, digest: &CredentialDigest) -> Option<TokenRejection> {
        self.memos().negative.get(digest.as_bytes()).copied()
    }

    async fn resolve(
        &self,
        digest: &CredentialDigest,
        verify: Verification<'_>,
    ) -> Result<TokenIdentity, TokenRejection> {
        let memoized = self.memos().positive.get(digest.as_bytes()).cloned();
        if let Some(identity) = memoized {
            return Ok(identity);
        }
        self.verifications.fetch_add(1, Ordering::AcqRel);
        let outcome = verify();
        let mut memos = self.memos();
        match &outcome {
            Ok(identity) => {
                memos.positive.insert(*digest.as_bytes(), identity.clone());
            }
            Err(rejection) => {
                memos.negative.insert(*digest.as_bytes(), *rejection);
            }
        }
        outcome
    }

    async fn flush(&self) {
        self.flushes.fetch_add(1, Ordering::AcqRel);
        let mut memos = self.memos();
        memos.positive.clear();
        memos.negative.clear();
    }
}

/// A token repository that answers from a table of raw credentials: a blank credential is
/// missing, a registered one yields its outcome, any other one is invalid. It counts its calls.
#[derive(Debug, Default)]
pub struct FakeTokenRepository {
    outcomes: Mutex<BTreeMap<String, Result<TokenIdentity, TokenRejection>>>,
    calls: AtomicUsize,
}

impl FakeTokenRepository {
    /// A repository that knows no credential.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `raw` resolve to `identity`.
    #[must_use]
    pub fn accepting(self, raw: &str, identity: TokenIdentity) -> Self {
        self.answer(raw, Ok(identity))
    }

    /// Makes `raw` be refused with `rejection`.
    #[must_use]
    pub fn rejecting(self, raw: &str, rejection: TokenRejection) -> Self {
        self.answer(raw, Err(rejection))
    }

    /// How many credentials were resolved.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }

    fn answer(self, raw: &str, outcome: Result<TokenIdentity, TokenRejection>) -> Self {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(raw.to_owned(), outcome);
        self
    }
}

#[async_trait]
impl TokenRepository for FakeTokenRepository {
    async fn resolve(&self, credential: &Credential) -> Result<TokenIdentity, TokenRejection> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if credential.is_blank() {
            return Err(TokenRejection::Missing);
        }
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(credential.expose())
            .cloned()
            .unwrap_or(Err(TokenRejection::Invalid))
    }
}

#[cfg(test)]
mod tests;
