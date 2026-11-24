//! Lists routes with cursor pagination and the filters host, upstream and service (FR-57).

use std::sync::Arc;

use iam_domain::{
    RouteHost, RouteId, RoutePageQuery, RouteParts, RouteRepository, ServiceName, UpstreamId,
};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of routes.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the routes that are not deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRoutesQuery {
    /// The largest number of routes of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last route of the previous page; none for the first page.
    pub after: Option<RouteId>,
    /// Only routes of this host.
    pub host: Option<RouteHost>,
    /// Only routes that forward to this upstream.
    pub upstream: Option<UpstreamId>,
    /// Only routes of this catalogue service.
    pub service: Option<ServiceName>,
}

/// One page of routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePage {
    /// The routes of the page, in the stable order of the repository.
    pub routes: Vec<RouteParts>,
    /// The cursor of the next page: the last route of this one; none when no route follows.
    pub next_after: Option<RouteId>,
}

impl Query for ListRoutesQuery {
    type Output = RoutePage;
    type Error = IamError;
    const NAME: &'static str = "ListRoutesQuery";
}

/// Handles [`ListRoutesQuery`].
///
/// It reads one route more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct ListRoutesQueryHandler {
    routes: Arc<dyn RouteRepository>,
}

impl ListRoutesQueryHandler {
    /// A handler over the route repository.
    #[must_use]
    pub const fn new(routes: Arc<dyn RouteRepository>) -> Self {
        Self { routes }
    }

    async fn list(&self, query: ListRoutesQuery) -> Result<RoutePage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = RoutePageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
            host: query.host,
            upstream: query.upstream,
            service: query.service,
        };
        let mut routes: Vec<RouteParts> = self
            .routes
            .find_page(&read)
            .await?
            .iter()
            .map(|route| route.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = routes
            .get(size.saturating_sub(1))
            .filter(|_last| routes.len() > size)
            .map(|last| last.id);
        routes.truncate(size);
        Ok(RoutePage { routes, next_after })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListRoutesQuery> for ListRoutesQueryHandler {
    async fn handle(&self, query: ListRoutesQuery) -> Result<RoutePage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
