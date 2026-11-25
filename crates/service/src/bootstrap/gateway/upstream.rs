//! `HyperUpstreamForwarder`: the adapter of the `UpstreamForwarder` port that hands an authorized
//! request to an endpoint of its upstream (FR-59, FR-87, architecture section 4.4).
//!
//! The adapter lives in the composition root under the ADR 0023 fallback, because it owns the
//! streamed request body and the timers, which may use `tokio` and `hyper` directly.
//!
//! What it does in its first form (Story 10.3):
//!
//! - the endpoint comes from the [`EndpointSelector`] over the endpoints that the directory offers
//!   for the Service of the upstream, with the requests this forwarder has in flight to each;
//! - the connection is pooled: HTTP/1.1 keep-alive, or one cleartext HTTP/2 connection per
//!   endpoint, by the `protocol` of the upstream;
//! - the connect timeout applies here with `tokio::time`, around the connector;
//! - the request body is streamed under the body limit of the route, and a declared length above
//!   it is refused before any connection is made;
//! - the response is relayed as it arrives, without buffering, and hop-by-hop headers are removed
//!   from the request and from the response.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::CONTENT_LENGTH;
use axum::http::uri::{PathAndQuery, Scheme};
use axum::http::{HeaderMap, Uri, Version};
use axum::response::Response;
use http_body_util::{LengthLimitError, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::{Client, Error as ClientError};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use iam_application::EndpointView;
use iam_domain::endpoint::selector::{Candidate, DEFAULT_SPILL_THRESHOLD};
use iam_domain::{
    EndpointSelector, ForwardError, Rng, UpstreamEndpoint, UpstreamForwarder, UpstreamProtocol,
    UpstreamTarget,
};
use tower::Service;

/// The headers that describe one connection and are never forwarded (RFC 9110, section 7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The request as the client sends it: the body of the caller under the limit of the route.
type Outgoing = axum::http::Request<Limited<Body>>;

/// The pooled client of one protocol and one connect timeout.
type UpstreamClient = Client<TimedConnector<HttpConnector>, Limited<Body>>;

/// What tells two pooled clients apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientKey {
    http2: bool,
    connect_ms: u32,
}

/// No connection to the endpoint was established within the connect timeout.
#[derive(Debug, thiserror::Error)]
#[error("the connection to the endpoint timed out")]
struct ConnectTimedOut;

/// The connector of the pooled clients: a connector under the connect timeout.
#[derive(Debug, Clone)]
struct TimedConnector<C> {
    inner: C,
    timeout: Duration,
}

type ConnectError = Box<dyn StdError + Send + Sync>;

impl<C> Service<Uri> for TimedConnector<C>
where
    C: Service<Uri>,
    C::Response: Send + 'static,
    C::Error: Into<ConnectError>,
    C::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<C::Response, ConnectError>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), ConnectError>> {
        self.inner.poll_ready(context).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connecting = self.inner.call(uri);
        let limit = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(limit, connecting).await {
                Ok(connected) => connected.map_err(Into::into),
                Err(_elapsed) => Err(ConnectTimedOut.into()),
            }
        })
    }
}

/// The requests in flight to each endpoint, counted while a [`InFlight`] guard lives.
type InFlightCounts = Arc<Mutex<HashMap<String, u32>>>;

/// One request in flight to an endpoint, counted until the guard drops.
#[derive(Debug)]
struct InFlight {
    counts: InFlightCounts,
    endpoint: String,
}

impl InFlight {
    fn enter(counts: &InFlightCounts, endpoint: String) -> Self {
        let mut held = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(endpoint.clone()).or_insert(0);
        *count = count.saturating_add(1);
        drop(held);
        Self {
            counts: Arc::clone(counts),
            endpoint,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut held = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        held.entry(self.endpoint.clone())
            .and_modify(|count| *count = count.saturating_sub(1));
        held.retain(|_endpoint, count| *count > 0);
    }
}

/// Forwards requests over pooled hyper clients to the endpoints that the directory offers.
#[derive(Debug)]
pub struct HyperUpstreamForwarder {
    endpoints: EndpointView,
    zone_aware: bool,
    rng: Arc<dyn Rng>,
    clients: Mutex<HashMap<ClientKey, UpstreamClient>>,
    in_flight: InFlightCounts,
}

impl HyperUpstreamForwarder {
    /// A forwarder over the endpoints of `endpoints`; `zone_aware` is `UPSTREAM_ZONE_AWARE` and
    /// `rng` supplies the draws of the endpoint choice.
    #[must_use]
    pub fn new(endpoints: EndpointView, zone_aware: bool, rng: Arc<dyn Rng>) -> Self {
        Self {
            endpoints,
            zone_aware,
            rng,
            clients: Mutex::new(HashMap::new()),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn deliver(
        &self,
        target: UpstreamTarget,
        request: Request,
    ) -> Result<Response, ForwardError> {
        if declared_above(request.headers(), target.body_limit()) {
            return Err(ForwardError::BodyTooLarge);
        }
        let endpoint = self.choose(&target)?;
        let _in_flight = InFlight::enter(&self.in_flight, endpoint_key(&endpoint));
        let outgoing = outgoing(request, &endpoint, &target)?;
        let wait = Duration::from_millis(u64::from(target.response_timeout_ms()));
        let answer = tokio::time::timeout(wait, self.client(&target).request(outgoing)).await;
        match answer {
            Ok(Ok(response)) => Ok(relayed(response)),
            Ok(Err(error)) => Err(classify(&error)),
            Err(_elapsed) => Err(ForwardError::ResponseTimeout),
        }
    }

    /// The endpoint of a new request: the selector over the offered endpoints of the Service.
    fn choose(&self, target: &UpstreamTarget) -> Result<UpstreamEndpoint, ForwardError> {
        let offered = self.endpoints.offered(target.service());
        let counts = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let candidates: Vec<Candidate<'_>> = offered
            .iter()
            .map(|endpoint| Candidate {
                endpoint,
                in_flight: counts.get(&endpoint_key(endpoint)).copied().unwrap_or(0),
            })
            .collect();
        let selector = EndpointSelector::new(
            self.endpoints.own_zone(),
            self.zone_aware,
            DEFAULT_SPILL_THRESHOLD,
        );
        let chosen = selector.select(&candidates, self.rng.as_ref());
        drop(candidates);
        drop(counts);
        chosen
            .and_then(|index| offered.into_iter().nth(index))
            .ok_or(ForwardError::NoEndpoint)
    }

    /// The pooled client for the protocol and the connect timeout of `target`, built on first use.
    fn client(&self, target: &UpstreamTarget) -> UpstreamClient {
        let key = ClientKey {
            http2: target.protocol() == UpstreamProtocol::H2c,
            connect_ms: target.connect_timeout_ms(),
        };
        self.clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_insert_with(|| build_client(key))
            .clone()
    }
}

#[async_trait::async_trait]
impl UpstreamForwarder for HyperUpstreamForwarder {
    type Request = Request;
    type Response = Response;

    async fn forward(
        &self,
        target: UpstreamTarget,
        request: Request,
    ) -> Result<Response, ForwardError> {
        self.deliver(target, request).await
    }
}

fn build_client(key: ClientKey) -> UpstreamClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    let timed = TimedConnector {
        inner: connector,
        timeout: Duration::from_millis(u64::from(key.connect_ms)),
    };
    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_timer(TokioTimer::new()).http2_only(key.http2);
    builder.build(timed)
}

/// The key of an endpoint in the in-flight counts.
fn endpoint_key(endpoint: &UpstreamEndpoint) -> String {
    format!("{}:{}", endpoint.address(), endpoint.port())
}

/// Whether the request declares a body above `limit`, so that it is refused before a connection
/// is made.
fn declared_above(headers: &HeaderMap, limit: u64) -> bool {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limit)
}

/// The request for the endpoint: its absolute target, the protocol version, no hop-by-hop headers
/// and a body that fails when it exceeds the limit of the route.
fn outgoing(
    request: Request,
    endpoint: &UpstreamEndpoint,
    target: &UpstreamTarget,
) -> Result<Outgoing, ForwardError> {
    let (mut parts, body) = request.into_parts();
    parts.uri = absolute(endpoint, &parts.uri).ok_or(ForwardError::NoEndpoint)?;
    parts.version = match target.protocol() {
        UpstreamProtocol::Http1 => Version::HTTP_11,
        UpstreamProtocol::H2c => Version::HTTP_2,
    };
    strip_hop_by_hop(&mut parts.headers);
    let limit = usize::try_from(target.body_limit()).unwrap_or(usize::MAX);
    Ok(axum::http::Request::from_parts(
        parts,
        Limited::new(body, limit),
    ))
}

/// The target of the request on `endpoint`: the path and query that the pipeline decided on.
fn absolute(endpoint: &UpstreamEndpoint, uri: &Uri) -> Option<Uri> {
    let address = endpoint.address();
    let authority = if address.contains(':') {
        format!("[{address}]:{}", endpoint.port())
    } else {
        format!("{address}:{}", endpoint.port())
    };
    let path = uri.path_and_query().map_or("/", PathAndQuery::as_str);
    Uri::builder()
        .scheme(Scheme::HTTP)
        .authority(authority)
        .path_and_query(path)
        .build()
        .ok()
}

/// Removes the headers of the connection: the fixed list and every header that `Connection`
/// names.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    for name in named.iter().map(String::as_str).chain(HOP_BY_HOP) {
        headers.remove(name);
    }
}

/// The response of the upstream as the caller receives it: the body is relayed as it arrives.
fn relayed(response: axum::http::Response<hyper::body::Incoming>) -> Response {
    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, Body::new(body))
}

/// Why a request that was handed to the client did not get a response.
fn classify(error: &ClientError) -> ForwardError {
    let root: &(dyn StdError + 'static) = error;
    let causes: Vec<&(dyn StdError + 'static)> =
        std::iter::successors(Some(root), |&cause| cause.source()).collect();
    if causes.iter().any(|cause| cause.is::<LengthLimitError>()) {
        ForwardError::BodyTooLarge
    } else if causes.iter().any(|cause| cause.is::<ConnectTimedOut>()) {
        ForwardError::ConnectTimeout
    } else if error.is_connect() {
        ForwardError::NotSent
    } else {
        ForwardError::Upstream
    }
}

#[cfg(test)]
mod tests;
