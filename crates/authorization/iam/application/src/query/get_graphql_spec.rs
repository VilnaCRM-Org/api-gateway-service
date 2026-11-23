//! Reads one GraphQL specification version, with its SDL when asked for (FR-1, FR-31).

use std::sync::Arc;

use iam_domain::{GraphQlSpecRepository, SpecId};
use shared_domain::{Query, QueryHandler};

use super::get_graphql_specs::{GraphQlSpecSummary, summarise};
use crate::error::IamError;

/// Asks for the version with the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetGraphQlSpecQuery {
    /// The version to read.
    pub id: SpecId,
    /// Whether the version carries its SDL.
    pub include_sdl: bool,
}

impl Query for GetGraphQlSpecQuery {
    type Output = Option<GraphQlSpecSummary>;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlSpecQuery";
}

/// Handles [`GetGraphQlSpecQuery`]: the version, or none when it is unknown.
#[derive(Debug)]
pub struct GetGraphQlSpecQueryHandler {
    specs: Arc<dyn GraphQlSpecRepository>,
}

impl GetGraphQlSpecQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn GraphQlSpecRepository>) -> Self {
        Self { specs }
    }

    async fn get(
        &self,
        query: GetGraphQlSpecQuery,
    ) -> Result<Option<GraphQlSpecSummary>, IamError> {
        let Some(spec) = self.specs.find_by_id(query.id).await? else {
            return Ok(None);
        };
        Ok(Some(
            summarise(self.specs.as_ref(), &spec, query.include_sdl).await?,
        ))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlSpecQuery> for GetGraphQlSpecQueryHandler {
    async fn handle(
        &self,
        query: GetGraphQlSpecQuery,
    ) -> Result<Option<GraphQlSpecSummary>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
