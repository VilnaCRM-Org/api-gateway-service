//! Reads the full route set of one host (FR-58).

use std::sync::Arc;

use iam_domain::{EntityVersion, RouteHost, RouteParts, RouteRepository, RouteSetVersion};
use shared_domain::{Query, QueryHandler};

use crate::command::route_configuration_plan::host_of;
use crate::error::IamError;

/// Asks for the routes of the host that are not deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRouteConfigurationQuery {
    /// The host name; a text that is not a host name is a violation of `host`.
    pub host: String,
}

/// The route set of one host and its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfiguration {
    /// The host.
    pub host: RouteHost,
    /// The routes of the host, by path pattern and methods.
    pub routes: Vec<RouteParts>,
    /// The version of the set, the `ETag` that a later application names as the version it
    /// replaces.
    pub version: EntityVersion,
}

impl Query for GetRouteConfigurationQuery {
    type Output = RouteConfiguration;
    type Error = IamError;
    const NAME: &'static str = "GetRouteConfigurationQuery";
}

/// Handles [`GetRouteConfigurationQuery`]: every route of the host, which is none for a host
/// without routes.
#[derive(Debug)]
pub struct GetRouteConfigurationQueryHandler {
    routes: Arc<dyn RouteRepository>,
}

impl GetRouteConfigurationQueryHandler {
    /// A handler over the route repository.
    #[must_use]
    pub const fn new(routes: Arc<dyn RouteRepository>) -> Self {
        Self { routes }
    }

    async fn get(&self, query: GetRouteConfigurationQuery) -> Result<RouteConfiguration, IamError> {
        let host = host_of(&query.host)?;
        let mut routes: Vec<RouteParts> = self
            .routes
            .find_by_host(&host)
            .await?
            .iter()
            .map(|route| route.parts().clone())
            .collect();
        routes.sort_by(|first, second| {
            (first.fields.path_pattern().as_str(), first.fields.methods()).cmp(&(
                second.fields.path_pattern().as_str(),
                second.fields.methods(),
            ))
        });
        let version = RouteSetVersion::of(&routes);
        Ok(RouteConfiguration {
            host,
            routes,
            version,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRouteConfigurationQuery> for GetRouteConfigurationQueryHandler {
    async fn handle(
        &self,
        query: GetRouteConfigurationQuery,
    ) -> Result<RouteConfiguration, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
