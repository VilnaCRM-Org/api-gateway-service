//! Access token verifier double.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use iam_domain::{AccessToken, AccessTokenVerifier, Credential, TokenRejection};

/// The committed development key file `config/jwt/dev-public-keys.pem`.
///
/// It holds one RSA public key whose private half is not committed, so no token can be signed for
/// it. Tests whose configuration must name a valid `JWT_PUBLIC_KEYS_FILE` point at it.
pub const DEVELOPMENT_PUBLIC_KEYS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/jwt/dev-public-keys.pem"
);

/// A verifier that answers from a table of raw credentials: a blank credential is missing, a
/// registered one yields its outcome, any other one is invalid.
#[derive(Debug, Default)]
pub struct FakeAccessTokenVerifier {
    outcomes: Mutex<BTreeMap<String, Result<AccessToken, TokenRejection>>>,
    calls: Mutex<usize>,
    key_set_version: AtomicU64,
}

impl FakeAccessTokenVerifier {
    /// A verifier that knows no credential.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `raw` verify as `token`.
    #[must_use]
    pub fn accepting(self, raw: &str, token: AccessToken) -> Self {
        self.answer(raw, Ok(token))
    }

    /// Makes `raw` be refused with `rejection`.
    #[must_use]
    pub fn rejecting(self, raw: &str, rejection: TokenRejection) -> Self {
        self.answer(raw, Err(rejection))
    }

    /// How many credentials were verified.
    #[must_use]
    pub fn calls(&self) -> usize {
        *self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Simulates a reload of the trusted key set: the next [`AccessTokenVerifier::key_set_version`]
    /// is one higher.
    pub fn rotate_keys(&self) {
        self.key_set_version.fetch_add(1, Ordering::AcqRel);
    }

    fn answer(self, raw: &str, outcome: Result<AccessToken, TokenRejection>) -> Self {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(raw.to_owned(), outcome);
        self
    }
}

impl AccessTokenVerifier for FakeAccessTokenVerifier {
    fn verify(&self, credential: &Credential) -> Result<AccessToken, TokenRejection> {
        {
            let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
            *calls = calls.saturating_add(1);
        }
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

    fn key_set_version(&self) -> u64 {
        self.key_set_version.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests;
