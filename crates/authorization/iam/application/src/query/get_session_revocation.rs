//! Reads one session revocation (FR-81).

use std::sync::Arc;

use iam_domain::{RevocationRepository, SessionRevocation, SessionRevocationId};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the session revocation with the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetSessionRevocationQuery {
    /// The revocation to read.
    pub id: SessionRevocationId,
}

impl Query for GetSessionRevocationQuery {
    type Output = Option<SessionRevocation>;
    type Error = IamError;
    const NAME: &'static str = "GetSessionRevocationQuery";
}

/// Handles [`GetSessionRevocationQuery`]: the revocation with its source and actor, or none when
/// it is unknown.
#[derive(Debug)]
pub struct GetSessionRevocationQueryHandler {
    revocations: Arc<dyn RevocationRepository>,
}

impl GetSessionRevocationQueryHandler {
    /// A handler over the revocation repository.
    #[must_use]
    pub const fn new(revocations: Arc<dyn RevocationRepository>) -> Self {
        Self { revocations }
    }

    async fn get(
        &self,
        query: GetSessionRevocationQuery,
    ) -> Result<Option<SessionRevocation>, IamError> {
        Ok(self.revocations.session_revocation_by_id(query.id).await?)
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetSessionRevocationQuery> for GetSessionRevocationQueryHandler {
    async fn handle(
        &self,
        query: GetSessionRevocationQuery,
    ) -> Result<Option<SessionRevocation>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
