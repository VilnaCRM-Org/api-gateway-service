//! Route read port (board name `RouteRepository`).

use crate::port::RepositoryError;
use crate::route::Route;
use crate::value_object::identifier::{RatePolicyId, RouteId, UpstreamId};
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;

/// One page of routes to read: at most `limit` routes after the cursor, filtered by host,
/// upstream and service. The caller validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePageQuery {
    /// The largest number of routes of the page.
    pub limit: u32,
    /// The last route of the previous page; `None` for the first page.
    pub after: Option<RouteId>,
    /// Only routes of this host.
    pub host: Option<RouteHost>,
    /// Only routes that forward to this upstream.
    pub upstream: Option<UpstreamId>,
    /// Only routes of this catalogue service.
    pub service: Option<ServiceName>,
}

/// Reads `Route` aggregates. Routes are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork), as statements of an administrative change.
#[async_trait::async_trait]
pub trait RouteRepository: std::fmt::Debug + Send + Sync {
    /// The route with the identifier, unless it is unknown or deleted.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: RouteId) -> Result<Option<Route>, RepositoryError>;

    /// One page of routes that are not deleted, in a stable order in which every matching route
    /// appears exactly once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(&self, query: &RoutePageQuery) -> Result<Vec<Route>, RepositoryError>;

    /// Every route of the host that is not deleted: the full host configuration.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_host(&self, host: &RouteHost) -> Result<Vec<Route>, RepositoryError>;

    /// The number of routes that are not deleted and forward to the upstream.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn count_by_upstream(&self, upstream: UpstreamId) -> Result<u64, RepositoryError>;

    /// The number of routes that are not deleted and apply the rate policy.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn count_by_rate_policy(&self, policy: RatePolicyId) -> Result<u64, RepositoryError>;
}
