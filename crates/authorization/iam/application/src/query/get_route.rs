//! Reads one route by its identifier (FR-57).

use std::sync::Arc;

use iam_domain::{RouteId, RouteParts, RouteRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the route with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetRouteQuery {
    /// The route to read.
    pub id: RouteId,
}

impl Query for GetRouteQuery {
    type Output = Option<RouteParts>;
    type Error = IamError;
    const NAME: &'static str = "GetRouteQuery";
}

/// Handles [`GetRouteQuery`]: the state of the route, or none when it is unknown or deleted.
#[derive(Debug)]
pub struct GetRouteQueryHandler {
    routes: Arc<dyn RouteRepository>,
}

impl GetRouteQueryHandler {
    /// A handler over the route repository.
    #[must_use]
    pub const fn new(routes: Arc<dyn RouteRepository>) -> Self {
        Self { routes }
    }

    async fn get(&self, query: GetRouteQuery) -> Result<Option<RouteParts>, IamError> {
        let route = self.routes.find_by_id(query.id).await?;
        Ok(route.map(|route| route.parts().clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRouteQuery> for GetRouteQueryHandler {
    async fn handle(&self, query: GetRouteQuery) -> Result<Option<RouteParts>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
