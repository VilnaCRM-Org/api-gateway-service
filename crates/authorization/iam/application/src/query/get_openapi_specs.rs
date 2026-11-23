//! Lists `OpenAPI` specification versions with cursor pagination and filters (FR-1, FR-35).

use std::sync::Arc;

use iam_domain::{
    OpenApiSpec, OpenApiSpecPageQuery, OpenApiSpecParts, OpenApiSpecRepository, ServiceName,
    SpecId, SpecStatus,
};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of versions.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of `OpenAPI` specification versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOpenApiSpecsQuery {
    /// The largest number of versions of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last version of the previous page; none for the first page.
    pub after: Option<SpecId>,
    /// Only versions of this service.
    pub service: Option<ServiceName>,
    /// Only versions in this status.
    pub status: Option<SpecStatus>,
    /// Whether each version carries its document.
    pub include_document: bool,
}

/// A version without its diff: the stored state, the number of operations and, when asked for, the
/// document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecSummary {
    /// The state of the version.
    pub spec: OpenApiSpecParts,
    /// The number of operations of the version.
    pub operation_count: usize,
    /// The `OpenAPI` document; none unless the caller asked for it.
    pub document: Option<String>,
}

/// One page of versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecPage {
    /// The versions of the page, in the stable order of the repository.
    pub specs: Vec<OpenApiSpecSummary>,
    /// The cursor of the next page: the last version of this one; none when none follows.
    pub next_after: Option<SpecId>,
}

impl Query for GetOpenApiSpecsQuery {
    type Output = OpenApiSpecPage;
    type Error = IamError;
    const NAME: &'static str = "GetOpenApiSpecsQuery";
}

/// The summary of a stored version; the document is read only when `include_document` is set.
///
/// # Errors
///
/// [`IamError::Storage`] when the document cannot be read.
pub(super) async fn summarise(
    specs: &dyn OpenApiSpecRepository,
    spec: &OpenApiSpec,
    include_document: bool,
) -> Result<OpenApiSpecSummary, IamError> {
    let parts = spec.parts().clone();
    let document = if include_document {
        specs.find_document(parts.id).await?
    } else {
        None
    };
    Ok(OpenApiSpecSummary {
        operation_count: spec.operations().len(),
        spec: parts,
        document,
    })
}

/// Handles [`GetOpenApiSpecsQuery`].
///
/// It reads one version more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct GetOpenApiSpecsQueryHandler {
    specs: Arc<dyn OpenApiSpecRepository>,
}

impl GetOpenApiSpecsQueryHandler {
    /// A handler over the specification repository.
    #[must_use]
    pub const fn new(specs: Arc<dyn OpenApiSpecRepository>) -> Self {
        Self { specs }
    }

    async fn list(&self, query: GetOpenApiSpecsQuery) -> Result<OpenApiSpecPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = OpenApiSpecPageQuery {
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
            summaries.push(summarise(self.specs.as_ref(), spec, query.include_document).await?);
        }
        Ok(OpenApiSpecPage {
            specs: summaries,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetOpenApiSpecsQuery> for GetOpenApiSpecsQueryHandler {
    async fn handle(&self, query: GetOpenApiSpecsQuery) -> Result<OpenApiSpecPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
