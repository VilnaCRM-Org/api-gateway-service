//! The token repository of one batch: each distinct credential is resolved once.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{Credential, TokenIdentity, TokenRejection, TokenRepository};

/// What one resolution answered.
type Resolution = Result<TokenIdentity, TokenRejection>;

/// Remembers every answer of the repository it wraps for as long as it lives, which is one
/// batch. A refusal is remembered as well as an identity, so a credential that the repository
/// could not read is not asked again within the batch either.
#[derive(Debug)]
pub(crate) struct BatchTokenMemo {
    tokens: Arc<dyn TokenRepository>,
    resolved: Mutex<BTreeMap<String, Resolution>>,
}

impl BatchTokenMemo {
    /// An empty memo over `tokens`.
    pub(crate) fn new(tokens: Arc<dyn TokenRepository>) -> Self {
        Self {
            tokens,
            resolved: Mutex::new(BTreeMap::new()),
        }
    }

    fn remembered(&self, credential: &Credential) -> Option<Resolution> {
        self.resolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(credential.expose())
            .cloned()
    }

    fn remember(&self, credential: &Credential, resolution: &Resolution) {
        self.resolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(credential.expose().to_owned(), resolution.clone());
    }

    async fn resolve_once(&self, credential: &Credential) -> Resolution {
        if let Some(resolution) = self.remembered(credential) {
            return resolution;
        }
        let resolution = self.tokens.resolve(credential).await;
        self.remember(credential, &resolution);
        resolution
    }
}

#[async_trait]
impl TokenRepository for BatchTokenMemo {
    async fn resolve(&self, credential: &Credential) -> Resolution {
        self.resolve_once(credential).await
    }
}

#[cfg(test)]
mod tests;
