//! Resolves a credential that a caller presents for someone else: the token-resolution API (FR-19).

use std::sync::Arc;

use iam_domain::{Credential, TokenRejection, TokenRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;
use crate::principal::Principal;

/// Asks who the bearer of a credential is, on behalf of an authenticated caller.
#[derive(Debug, Clone)]
pub struct ResolveSubjectTokenQuery {
    /// The credential to resolve; blank when the caller sent an empty one.
    pub credential: Credential,
}

/// The answer to a [`ResolveSubjectTokenQuery`]: a refused credential is an answer, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenResolution {
    /// The credential is valid and unrevoked; this is its bearer.
    Resolved(Principal),
    /// The credential is refused for this reason.
    Unresolved(TokenRejection),
}

impl Query for ResolveSubjectTokenQuery {
    type Output = TokenResolution;
    type Error = IamError;
    const NAME: &'static str = "ResolveSubjectTokenQuery";
}

/// Handles [`ResolveSubjectTokenQuery`].
///
/// It runs the memoized verification and the revocation check of the [`TokenRepository`]. The
/// caller rule of service principals does not apply: it limits who may call IAM, and this
/// credential is the subject of the question, not the caller.
#[derive(Debug)]
pub struct ResolveSubjectTokenQueryHandler {
    tokens: Arc<dyn TokenRepository>,
}

impl ResolveSubjectTokenQueryHandler {
    /// A handler over the token repository.
    #[must_use]
    pub const fn new(tokens: Arc<dyn TokenRepository>) -> Self {
        Self { tokens }
    }

    async fn resolve(&self, query: &ResolveSubjectTokenQuery) -> Result<TokenResolution, IamError> {
        match self.tokens.resolve(&query.credential).await {
            Ok(identity) => Ok(TokenResolution::Resolved(Principal::from(identity))),
            Err(unavailable @ TokenRejection::Unavailable) => Err(IamError::from(unavailable)),
            Err(rejection) => Ok(TokenResolution::Unresolved(rejection)),
        }
    }
}

#[async_trait::async_trait]
impl QueryHandler<ResolveSubjectTokenQuery> for ResolveSubjectTokenQueryHandler {
    async fn handle(&self, query: ResolveSubjectTokenQuery) -> Result<TokenResolution, IamError> {
        self.resolve(&query).await
    }
}

#[cfg(test)]
mod tests;
