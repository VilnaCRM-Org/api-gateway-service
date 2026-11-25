//! Port that hands an authorized request to its upstream (FR-59, FR-66).

use crate::port::endpoint_watch::WatchTarget;
use crate::route::fields::RouteFields;
use crate::route::settings::{BodyLimit, RetryPolicy, RouteFlags};
use crate::upstream::settings::{UpstreamProtocol, UpstreamSettings};
use crate::value_object::identifier::RouteId;
use crate::value_object::upstream_name::UpstreamName;

/// The largest request body, in bytes, of a target whose route sets no limit: 10 MiB.
pub const DEFAULT_BODY_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

/// The connect timeout, in milliseconds, of a target whose upstream sets none.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 250;

/// The response timeout, in milliseconds, of a target whose upstream sets none.
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u32 = 10_000;

/// The time, in milliseconds, that a GraphQL route waits for the response headers when its
/// upstream keeps the default response timeout: 30 seconds.
pub const DEFAULT_GRAPHQL_RESPONSE_TIMEOUT_MS: u32 = 30_000;

/// The time, in milliseconds, that the whole request of a target may take when its route sets
/// none: 60 seconds. A streaming route has no such limit.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u32 = 60_000;

/// The concurrency limit of a target whose upstream sets none: no limit.
pub const DEFAULT_CONCURRENCY_LIMIT: u32 = u32::MAX;

/// The retry budget, in percent, of a target whose upstream sets none.
pub const DEFAULT_RETRY_BUDGET_PERCENT: u8 = 10;

/// The consecutive failures that eject an endpoint of a target whose upstream sets none.
pub const DEFAULT_OUTLIER_THRESHOLD: u32 = 5;

/// Where an authorized request goes.
///
/// It holds the upstream its route points to, the route that matched and how the request is
/// delivered (the Service that holds the endpoints, the protocol, the timeouts, the body limit and
/// whether the caller's credentials go along).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    upstream: UpstreamName,
    route: RouteId,
    service: WatchTarget,
    protocol: UpstreamProtocol,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    body_limit: u64,
    forward_credentials: bool,
    flags: RouteFlags,
    retry: RetryPolicy,
    request_timeout_ms: u32,
    concurrency_limit: u32,
    retry_budget_percent: u8,
    outlier_threshold: u32,
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
            forward_credentials: false,
            flags: RouteFlags::NONE,
            retry: RetryPolicy::None,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
            retry_budget_percent: DEFAULT_RETRY_BUDGET_PERCENT,
            outlier_threshold: DEFAULT_OUTLIER_THRESHOLD,
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
            forward_credentials: settings.forward_credentials(),
            concurrency_limit: settings.concurrency_limit(),
            retry_budget_percent: settings.retry_budget_percent(),
            outlier_threshold: settings.outlier_threshold(),
            ..self
        }
    }

    /// The target with the request body limit of its route.
    #[must_use]
    pub const fn with_body_limit(mut self, limit: BodyLimit) -> Self {
        self.body_limit = limit.bytes();
        self
    }

    /// The target delivered the way `route` says: its body limit, flags, retry policy and request
    /// timeout.
    #[must_use]
    pub const fn with_route(mut self, route: &RouteFields) -> Self {
        self.body_limit = route.body_limit().bytes();
        self.flags = route.flags();
        self.retry = route.retry();
        self.request_timeout_ms = route.timeouts().request_ms();
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

    /// The time allowed for the response headers, in milliseconds: the response timeout of the
    /// upstream, except that a GraphQL route whose upstream keeps the default gets 30 seconds.
    #[must_use]
    pub const fn headers_timeout_ms(&self) -> u32 {
        if self.flags.graphql() && self.response_timeout_ms == DEFAULT_RESPONSE_TIMEOUT_MS {
            DEFAULT_GRAPHQL_RESPONSE_TIMEOUT_MS
        } else {
            self.response_timeout_ms
        }
    }

    /// The time the whole request may take, in milliseconds; `None` for a streaming route.
    #[must_use]
    pub const fn request_timeout_ms(&self) -> Option<u32> {
        if self.flags.streaming() {
            None
        } else {
            Some(self.request_timeout_ms)
        }
    }

    /// Whether the route serves GraphQL.
    #[must_use]
    pub const fn graphql(&self) -> bool {
        self.flags.graphql()
    }

    /// Which failed requests the route retries.
    #[must_use]
    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    /// The most requests that the upstream has in flight at once.
    #[must_use]
    pub const fn concurrency_limit(&self) -> u32 {
        self.concurrency_limit
    }

    /// The share of the upstream's requests that may be retries, in percent.
    #[must_use]
    pub const fn retry_budget_percent(&self) -> u8 {
        self.retry_budget_percent
    }

    /// The consecutive failures after which an endpoint of the upstream is ejected.
    #[must_use]
    pub const fn outlier_threshold(&self) -> u32 {
        self.outlier_threshold
    }

    /// The largest request body the route accepts, in bytes.
    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.body_limit
    }

    /// Whether the upstream receives the caller's `Authorization` header and `__Host-auth_token`
    /// cookie (FR-68); every other upstream relies on the principal headers.
    #[must_use]
    pub const fn forward_credentials(&self) -> bool {
        self.forward_credentials
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
