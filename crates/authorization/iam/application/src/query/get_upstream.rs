//! Reads one upstream by its identifier (FR-56).

use std::sync::Arc;

use iam_domain::{UpstreamId, UpstreamParts, UpstreamRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the upstream with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetUpstreamQuery {
    /// The upstream to read.
    pub id: UpstreamId,
}

impl Query for GetUpstreamQuery {
    type Output = Option<UpstreamParts>;
    type Error = IamError;
    const NAME: &'static str = "GetUpstreamQuery";
}

/// Handles [`GetUpstreamQuery`]: the state of the upstream, or none when it is unknown or deleted.
#[derive(Debug)]
pub struct GetUpstreamQueryHandler {
    upstreams: Arc<dyn UpstreamRepository>,
}

impl GetUpstreamQueryHandler {
    /// A handler over the upstream repository.
    #[must_use]
    pub const fn new(upstreams: Arc<dyn UpstreamRepository>) -> Self {
        Self { upstreams }
    }

    async fn get(&self, query: GetUpstreamQuery) -> Result<Option<UpstreamParts>, IamError> {
        let upstream = self.upstreams.find_by_id(query.id).await?;
        Ok(upstream.map(|upstream| upstream.parts().clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetUpstreamQuery> for GetUpstreamQueryHandler {
    async fn handle(&self, query: GetUpstreamQuery) -> Result<Option<UpstreamParts>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
