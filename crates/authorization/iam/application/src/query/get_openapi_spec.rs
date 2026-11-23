//! Reads one `OpenAPI` specification version, with its document when asked for (FR-1, FR-35).

use std::sync::Arc;

use iam_domain::{OpenApiSpecRepository, SpecId};
use shared_domain::{Query, QueryHandler};

use super::get_openapi_specs::{OpenApiSpecSummary, summarise};
use crate::error::IamError;

/// Asks for the version with the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetOpenApiSpecQuery {
    /// The version to read.
    pub id: SpecId,
    /// Whether the version carries its document.
    pub include_document: bool,
}

impl Query for GetOpenApiSpecQuery {
    type Output = Option<OpenApiSpecSummary>;
    type Error = IamError;
    const NAME: &'static str = "GetOpenApiSpecQuery";
}

/// Handles [`GetOpenApiSpecQuery`]: the version, or none when it is unknown.
#[derive(Debug)]
pub struct GetOpenApiSpecQueryHandler {
    specs: Arc<dyn OpenApiSpecRepository>,
}

impl GetOpenApiSpecQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn OpenApiSpecRepository>) -> Self {
        Self { specs }
    }

    async fn get(
        &self,
        query: GetOpenApiSpecQuery,
    ) -> Result<Option<OpenApiSpecSummary>, IamError> {
        let Some(spec) = self.specs.find_by_id(query.id).await? else {
            return Ok(None);
        };
        Ok(Some(
            summarise(self.specs.as_ref(), &spec, query.include_document).await?,
        ))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetOpenApiSpecQuery> for GetOpenApiSpecQueryHandler {
    async fn handle(
        &self,
        query: GetOpenApiSpecQuery,
    ) -> Result<Option<OpenApiSpecSummary>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
