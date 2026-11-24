//! Reads the global token cut-off (FR-81).

use std::sync::Arc;

use iam_domain::{GlobalTokenCutoff, RevocationRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the global cut-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetGlobalTokenCutoffQuery;

impl Query for GetGlobalTokenCutoffQuery {
    type Output = Option<GlobalTokenCutoff>;
    type Error = IamError;
    const NAME: &'static str = "GetGlobalTokenCutoffQuery";
}

/// Handles [`GetGlobalTokenCutoffQuery`]: the cut-off with the instant it refuses tokens up to and
/// the actor that set it, or none when it was never set.
#[derive(Debug)]
pub struct GetGlobalTokenCutoffQueryHandler {
    revocations: Arc<dyn RevocationRepository>,
}

impl GetGlobalTokenCutoffQueryHandler {
    /// A handler over the revocation repository.
    #[must_use]
    pub const fn new(revocations: Arc<dyn RevocationRepository>) -> Self {
        Self { revocations }
    }

    async fn get(&self) -> Result<Option<GlobalTokenCutoff>, IamError> {
        Ok(self.revocations.global_cutoff().await?)
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGlobalTokenCutoffQuery> for GetGlobalTokenCutoffQueryHandler {
    async fn handle(
        &self,
        _query: GetGlobalTokenCutoffQuery,
    ) -> Result<Option<GlobalTokenCutoff>, IamError> {
        self.get().await
    }
}

#[cfg(test)]
mod tests;
