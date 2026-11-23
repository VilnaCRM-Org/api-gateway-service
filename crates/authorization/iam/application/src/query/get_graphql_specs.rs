//! Lists GraphQL specification versions with cursor pagination and filters (FR-1, FR-31).

use std::sync::Arc;

use iam_domain::{
    GraphQlSpec, GraphQlSpecPageQuery, GraphQlSpecParts, GraphQlSpecRepository, ServiceName,
    SpecId, SpecStatus,
};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of versions.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of GraphQL specification versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetGraphQlSpecsQuery {
    /// The largest number of versions of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last version of the previous page; none for the first page.
    pub after: Option<SpecId>,
    /// Only versions of this service.
    pub service: Option<ServiceName>,
    /// Only versions in this status.
    pub status: Option<SpecStatus>,
    /// Whether each version carries its SDL.
    pub include_sdl: bool,
}

/// A version without its diff: the stored state, the number of coordinates and, when asked for,
/// the SDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecSummary {
    /// The state of the version.
    pub spec: GraphQlSpecParts,
    /// The number of field coordinates of the version.
    pub coordinate_count: usize,
    /// The SDL document; none unless the caller asked for it.
    pub sdl: Option<String>,
}

/// One page of versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecPage {
    /// The versions of the page, in the stable order of the repository.
    pub specs: Vec<GraphQlSpecSummary>,
    /// The cursor of the next page: the last version of this one; none when none follows.
    pub next_after: Option<SpecId>,
}

impl Query for GetGraphQlSpecsQuery {
    type Output = GraphQlSpecPage;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlSpecsQuery";
}

/// The summary of a stored version; the SDL is read only when `include_sdl` is set.
///
/// # Errors
///
/// [`IamError::Storage`] when the SDL cannot be read.
pub(super) async fn summarise(
    specs: &dyn GraphQlSpecRepository,
    spec: &GraphQlSpec,
    include_sdl: bool,
) -> Result<GraphQlSpecSummary, IamError> {
    let parts = spec.parts().clone();
    let sdl = if include_sdl {
        specs.find_sdl(parts.id).await?
    } else {
        None
    };
    Ok(GraphQlSpecSummary {
        coordinate_count: spec.coordinates().len(),
        spec: parts,
        sdl,
    })
}

/// Handles [`GetGraphQlSpecsQuery`].
///
/// It reads one version more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct GetGraphQlSpecsQueryHandler {
    specs: Arc<dyn GraphQlSpecRepository>,
}

impl GetGraphQlSpecsQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn GraphQlSpecRepository>) -> Self {
        Self { specs }
    }

    async fn list(&self, query: GetGraphQlSpecsQuery) -> Result<GraphQlSpecPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = GraphQlSpecPageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
            service: query.service,
            status: query.status,
        };
        let mut found = self.specs.find_page(&read).await?;
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = found
            .get(size.saturating_sub(1))
            .filter(|_last| found.len() > size)
            .map(|last| last.parts().id);
        found.truncate(size);
        let mut summaries = Vec::with_capacity(found.len());
        for spec in &found {
            summaries.push(summarise(self.specs.as_ref(), spec, query.include_sdl).await?);
        }
        Ok(GraphQlSpecPage {
            specs: summaries,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlSpecsQuery> for GetGraphQlSpecsQueryHandler {
    async fn handle(&self, query: GetGraphQlSpecsQuery) -> Result<GraphQlSpecPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
