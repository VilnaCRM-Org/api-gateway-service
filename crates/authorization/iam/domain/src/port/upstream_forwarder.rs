//! Port that hands an authorized request to its upstream (FR-59, FR-66).

use crate::value_object::identifier::RouteId;
use crate::value_object::upstream_name::UpstreamName;

/// Where an authorized request goes: the upstream its route points to and the route that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    upstream: UpstreamName,
    route: RouteId,
}

impl UpstreamTarget {
    /// The target of `route`, which points to `upstream`.
    #[must_use]
    pub const fn new(upstream: UpstreamName, route: RouteId) -> Self {
        Self { upstream, route }
    }

    /// The upstream.
    #[must_use]
    pub const fn upstream(&self) -> &UpstreamName {
        &self.upstream
    }

    /// The route that matched the request.
    #[must_use]
    pub const fn route(&self) -> RouteId {
        self.route
    }
}

/// Why a request could not be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// The request provably never reached an endpoint.
    #[error("the request was not sent to an upstream endpoint")]
    NotSent,
    /// No connection to an endpoint was established in time.
    #[error("the connection to the upstream timed out")]
    ConnectTimeout,
    /// The upstream did not answer in time.
    #[error("the upstream did not answer in time")]
    ResponseTimeout,
    /// The upstream is at its concurrency limit.
    #[error("the upstream is overloaded")]
    Overloaded,
    /// The upstream has no endpoint to send the request to.
    #[error("the upstream has no endpoint")]
    NoEndpoint,
    /// The upstream failed after it received the request.
    #[error("the upstream failed")]
    Upstream,
}

/// Forwards a request to an endpoint of an upstream and returns its response.
///
/// The domain names no HTTP type, so the request and the response are associated types that the
/// composition root binds to its HTTP library.
#[async_trait::async_trait]
pub trait UpstreamForwarder: std::fmt::Debug + Send + Sync {
    /// The request that is forwarded.
    type Request: Send;
    /// The response that comes back.
    type Response: Send;

    /// Forwards `request` to `target`.
    ///
    /// # Errors
    ///
    /// The [`ForwardError`] that says why no response came back.
    async fn forward(
        &self,
        target: UpstreamTarget,
        request: Self::Request,
    ) -> Result<Self::Response, ForwardError>;
}

#[cfg(test)]
mod tests;
