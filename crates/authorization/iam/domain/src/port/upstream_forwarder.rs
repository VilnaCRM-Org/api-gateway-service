//! Port that hands an authorized request to its upstream (FR-59, FR-66).

use crate::port::endpoint_watch::WatchTarget;
use crate::route::settings::BodyLimit;
use crate::upstream::settings::{UpstreamProtocol, UpstreamSettings};
use crate::value_object::identifier::RouteId;
use crate::value_object::upstream_name::UpstreamName;

/// The largest request body, in bytes, of a target whose route sets no limit: 10 MiB.
pub const DEFAULT_BODY_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

/// The connect timeout, in milliseconds, of a target whose upstream sets none.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 250;

/// The response timeout, in milliseconds, of a target whose upstream sets none.
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u32 = 10_000;

/// Where an authorized request goes.
///
/// It holds the upstream its route points to, the route that matched and how the request is
/// delivered (the Service that holds the endpoints, the protocol, the timeouts and the body
/// limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    upstream: UpstreamName,
    route: RouteId,
    service: WatchTarget,
    protocol: UpstreamProtocol,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    body_limit: u64,
}

impl UpstreamTarget {
    /// The target of `route`, which points to `upstream`, with no Service to take endpoints from,
    /// HTTP/1.1 and the default timeouts and body limit.
    #[must_use]
    pub const fn new(upstream: UpstreamName, route: RouteId) -> Self {
        Self {
            upstream,
            route,
            service: WatchTarget {
                namespace: String::new(),
                service: String::new(),
            },
            protocol: UpstreamProtocol::Http1,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            response_timeout_ms: DEFAULT_RESPONSE_TIMEOUT_MS,
            body_limit: DEFAULT_BODY_LIMIT_BYTES,
        }
    }

    /// The target delivered the way `settings` of the upstream say: its Service, protocol and
    /// timeouts.
    #[must_use]
    pub fn with_settings(self, settings: &UpstreamSettings) -> Self {
        Self {
            service: WatchTarget {
                namespace: settings.namespace().to_owned(),
                service: settings.service_name().to_owned(),
            },
            protocol: settings.protocol(),
            connect_timeout_ms: settings.connect_timeout_ms(),
            response_timeout_ms: settings.response_timeout_ms(),
            ..self
        }
    }

    /// The target with the request body limit of its route.
    #[must_use]
    pub const fn with_body_limit(mut self, limit: BodyLimit) -> Self {
        self.body_limit = limit.bytes();
        self
    }

    /// The Service whose endpoints receive the request.
    #[must_use]
    pub const fn service(&self) -> &WatchTarget {
        &self.service
    }

    /// The protocol spoken to the endpoints.
    #[must_use]
    pub const fn protocol(&self) -> UpstreamProtocol {
        self.protocol
    }

    /// The time allowed to connect to an endpoint, in milliseconds.
    #[must_use]
    pub const fn connect_timeout_ms(&self) -> u32 {
        self.connect_timeout_ms
    }

    /// The time allowed for the response headers, in milliseconds.
    #[must_use]
    pub const fn response_timeout_ms(&self) -> u32 {
        self.response_timeout_ms
    }

    /// The largest request body the route accepts, in bytes.
    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.body_limit
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
    /// The request body is above the limit of its route.
    #[error("the request body is above the limit of the route")]
    BodyTooLarge,
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
