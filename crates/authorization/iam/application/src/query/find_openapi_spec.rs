//! Finds the version that holds a document with a given hash: an identical upload.

use std::sync::Arc;

use iam_domain::{ContentHash, OpenApiSpecRepository, ServiceName, SpecId};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the version of `service` whose document has `content_hash`.
#[derive(Debug, Clone)]
pub struct FindOpenApiSpecQuery {
    /// The service of the document.
    pub service: ServiceName,
    /// The SHA-256 hash of the document.
    pub content_hash: ContentHash,
}

impl Query for FindOpenApiSpecQuery {
    type Output = Option<SpecId>;
    type Error = IamError;
    const NAME: &'static str = "FindOpenApiSpecQuery";
}

/// Handles [`FindOpenApiSpecQuery`]: the identifier of the version, or none when the service has no
/// version with that hash.
#[derive(Debug)]
pub struct FindOpenApiSpecQueryHandler {
    specs: Arc<dyn OpenApiSpecRepository>,
}

impl FindOpenApiSpecQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn OpenApiSpecRepository>) -> Self {
        Self { specs }
    }

    async fn find(&self, query: FindOpenApiSpecQuery) -> Result<Option<SpecId>, IamError> {
        let spec = self
            .specs
            .find_by_content_hash(&query.service, &query.content_hash)
            .await?;
        Ok(spec.map(|spec| spec.parts().id))
    }
}

#[async_trait::async_trait]
impl QueryHandler<FindOpenApiSpecQuery> for FindOpenApiSpecQueryHandler {
    async fn handle(&self, query: FindOpenApiSpecQuery) -> Result<Option<SpecId>, IamError> {
        self.find(query).await
    }
}

#[cfg(test)]
mod tests;
