//! Authenticates a caller of IAM's own API from its bearer credential.

use std::sync::Arc;

use iam_domain::{CallerTokenRule, Credential, TokenRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;
use crate::principal::Principal;

/// Asks who the bearer of a credential is.
#[derive(Debug, Clone)]
pub struct ResolveTokenQuery {
    /// The credential from `Authorization: Bearer` or the `__Host-auth_token` cookie; blank when
    /// the caller presented none.
    pub credential: Credential,
}

impl Query for ResolveTokenQuery {
    type Output = Principal;
    type Error = IamError;
    const NAME: &'static str = "ResolveTokenQuery";
}

/// Handles [`ResolveTokenQuery`].
///
/// It runs the memoized verification and the revocation check of the [`TokenRepository`] (in
/// `iam-control` the revocation state is read from PostgreSQL; no liveness call is made to User
/// service), then the [`CallerTokenRule`] for service principals.
#[derive(Debug)]
pub struct ResolveTokenQueryHandler {
    tokens: Arc<dyn TokenRepository>,
    callers: CallerTokenRule,
}

impl ResolveTokenQueryHandler {
    /// A handler over the token repository and the caller rule.
    #[must_use]
    pub const fn new(tokens: Arc<dyn TokenRepository>, callers: CallerTokenRule) -> Self {
        Self { tokens, callers }
    }

    async fn resolve(&self, query: &ResolveTokenQuery) -> Result<Principal, IamError> {
        let identity = self.tokens.resolve(&query.credential).await?;
        self.callers.check(&identity)?;
        Ok(Principal::from(identity))
    }
}

#[async_trait::async_trait]
impl QueryHandler<ResolveTokenQuery> for ResolveTokenQueryHandler {
    async fn handle(&self, query: ResolveTokenQuery) -> Result<Principal, IamError> {
        self.resolve(&query).await
    }
}

#[cfg(test)]
mod tests;
