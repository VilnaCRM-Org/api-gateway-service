//! Lists upstreams with cursor pagination (FR-56).

use std::sync::Arc;

use iam_domain::{UpstreamId, UpstreamPageQuery, UpstreamParts, UpstreamRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of upstreams.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the upstreams that are not deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListUpstreamsQuery {
    /// The largest number of upstreams of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last upstream of the previous page; none for the first page.
    pub after: Option<UpstreamId>,
}

/// One page of upstreams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamPage {
    /// The upstreams of the page, in the stable order of the repository.
    pub upstreams: Vec<UpstreamParts>,
    /// The cursor of the next page: the last upstream of this one; none when no upstream follows.
    pub next_after: Option<UpstreamId>,
}

impl Query for ListUpstreamsQuery {
    type Output = UpstreamPage;
    type Error = IamError;
    const NAME: &'static str = "ListUpstreamsQuery";
}

/// Handles [`ListUpstreamsQuery`].
///
/// It reads one upstream more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct ListUpstreamsQueryHandler {
    upstreams: Arc<dyn UpstreamRepository>,
}

impl ListUpstreamsQueryHandler {
    /// A handler over the upstream repository.
    #[must_use]
    pub const fn new(upstreams: Arc<dyn UpstreamRepository>) -> Self {
        Self { upstreams }
    }

    async fn list(&self, query: ListUpstreamsQuery) -> Result<UpstreamPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = UpstreamPageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
        };
        let mut upstreams: Vec<UpstreamParts> = self
            .upstreams
            .find_page(&read)
            .await?
            .iter()
            .map(|upstream| upstream.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = upstreams
            .get(size.saturating_sub(1))
            .filter(|_last| upstreams.len() > size)
            .map(|last| last.id);
        upstreams.truncate(size);
        Ok(UpstreamPage {
            upstreams,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListUpstreamsQuery> for ListUpstreamsQueryHandler {
    async fn handle(&self, query: ListUpstreamsQuery) -> Result<UpstreamPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
