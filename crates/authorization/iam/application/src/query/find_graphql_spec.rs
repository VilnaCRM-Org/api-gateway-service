//! Finds the version of a service that holds an SDL with a given hash: an identical upload.

use std::sync::Arc;

use iam_domain::{ContentHash, GraphQlSpecRepository, ServiceName, SpecId};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the version of `service` whose SDL has `content_hash`.
#[derive(Debug, Clone)]
pub struct FindGraphQlSpecQuery {
    /// The service of the schema.
    pub service: ServiceName,
    /// The SHA-256 hash of the SDL.
    pub content_hash: ContentHash,
}

impl Query for FindGraphQlSpecQuery {
    type Output = Option<SpecId>;
    type Error = IamError;
    const NAME: &'static str = "FindGraphQlSpecQuery";
}

/// Handles [`FindGraphQlSpecQuery`]: the identifier of the version, or none when the service has no
/// version with that hash.
#[derive(Debug)]
pub struct FindGraphQlSpecQueryHandler {
    specs: Arc<dyn GraphQlSpecRepository>,
}

impl FindGraphQlSpecQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn GraphQlSpecRepository>) -> Self {
        Self { specs }
    }

    async fn find(&self, query: FindGraphQlSpecQuery) -> Result<Option<SpecId>, IamError> {
        let spec = self
            .specs
            .find_by_content_hash(&query.service, &query.content_hash)
            .await?;
        Ok(spec.map(|spec| spec.parts().id))
    }
}

#[async_trait::async_trait]
impl QueryHandler<FindGraphQlSpecQuery> for FindGraphQlSpecQueryHandler {
    async fn handle(&self, query: FindGraphQlSpecQuery) -> Result<Option<SpecId>, IamError> {
        self.find(query).await
    }
}

#[cfg(test)]
mod tests;
