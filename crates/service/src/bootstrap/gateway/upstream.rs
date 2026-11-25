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
//!
//! What it adds in Story 10.5 (FR-66):
//!
//! - the timeouts: the response headers (10 seconds, 30 for a GraphQL route) and the whole request
//!   (60 seconds, none for a streaming route), each overridable by the upstream and the route;
//! - at most one retry, to another endpoint, of a request that provably was not sent or of an
//!   idempotent request that the route allows to retry, within the retry budget of the upstream
//!   (the rules are `RetryRule` and `RetryBudget` of the domain);
//! - passive outlier ejection of an endpoint after consecutive connect errors or 5xx responses
//!   (`OutlierRule`), which the choice of the endpoint honours;
//! - the `concurrencyLimit` of the upstream, which fails fast with 503 `upstream_overloaded` and is
//!   held until the response body ends.

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
use axum::http::request::Parts;
use axum::http::uri::{PathAndQuery, Scheme};
use axum::http::{HeaderMap, Method, Uri, Version};
use axum::response::Response;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use iam_application::EndpointView;
use iam_domain::endpoint::selector::{Candidate, DEFAULT_SPILL_THRESHOLD};
use iam_domain::{
    Delivery, EndpointSelector, ForwardError, HttpMethod, OutlierRule, RequestBody, RetryCase,
    RetryRule, Rng, UpstreamEndpoint, UpstreamForwarder, UpstreamProtocol, UpstreamTarget,
};
use tokio::time::Instant;
use tower::Service;

use self::failure::{Classified, classify};
use self::payload::{Payload, ReplayBody};
use self::registry::{Permit, Registry};
use self::relay::RelayBody;

mod failure;
mod payload;
mod registry;
mod relay;

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

/// The pooled client of one protocol and one connect timeout.
type UpstreamClient = Client<TimedConnector<HttpConnector>, ReplayBody>;

/// The response of an endpoint before it is relayed to the caller.
type Answered = axum::http::Response<Incoming>;

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
    registry: Arc<Registry>,
}

/// The request as every attempt sends it, apart from its endpoint and its body.
#[derive(Debug)]
struct Template {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
}

/// What the attempts of one request share: where it goes, how it is sent and what it carries.
#[derive(Debug, Clone, Copy)]
struct Shared<'a> {
    target: &'a UpstreamTarget,
    template: &'a Template,
    payload: &'a Payload,
}

/// Why an attempt failed and whether the request provably did not reach the endpoint.
#[derive(Debug, Clone, Copy)]
struct Failure {
    error: ForwardError,
    delivery: Delivery,
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
            registry: Registry::new(),
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
        let deadline = deadline_of(&target);
        let (parts, body) = request.into_parts();
        // The body is read under the deadline and before the permit is taken: a client that
        // trickles it neither holds a slot of the upstream nor outlasts the request timeout.
        let buffering = Payload::prepare(body, target.body_limit(), buffers(&target, &parts));
        let payload = within(deadline, buffering).await??;
        let permit = self.registry.admit(&target)?;
        let template = Template::of(parts, &target);
        let shared = Shared {
            target: &target,
            template: &template,
            payload: &payload,
        };
        let attempts = self.attempts(shared);
        let answered = within(deadline, attempts).await??;
        Ok(relayed(answered, deadline, permit))
    }

    /// The first attempt and, when the rules allow it, one retry on another endpoint.
    async fn attempts(&self, shared: Shared<'_>) -> Result<Answered, ForwardError> {
        let first = self.choose(shared.target, None)?;
        let failure = match self.attempt(shared, &first).await {
            Ok(answered) => return Ok(answered),
            Err(failure) => failure,
        };
        let Some(second) = self.alternative(shared, failure, &first) else {
            return Err(failure.error);
        };
        self.attempt(shared, &second)
            .await
            .map_err(|failed| failed.error)
    }

    /// One attempt on `endpoint`: the response headers must arrive within the timeout.
    async fn attempt(
        &self,
        shared: Shared<'_>,
        endpoint: &UpstreamEndpoint,
    ) -> Result<Answered, Failure> {
        let Shared {
            target,
            template,
            payload,
        } = shared;
        let key = endpoint_key(endpoint);
        let _in_flight = InFlight::enter(&self.in_flight, key.clone());
        let request = template
            .request(endpoint, payload.body())
            .map_err(Failure::unsent)?;
        self.registry.count_request(target);
        let wait = Duration::from_millis(u64::from(target.headers_timeout_ms()));
        match tokio::time::timeout(wait, self.client(target).request(request)).await {
            Ok(Ok(answered)) => {
                self.settle(target, &key, answered.status().is_server_error());
                Ok(answered)
            }
            Ok(Err(error)) => Err(self.failed(target, &key, classify(&error))),
            Err(_elapsed) => Err(Failure {
                error: ForwardError::ResponseTimeout,
                delivery: Delivery::MaybeSent,
            }),
        }
    }

    /// The endpoint of the retry, when the failed attempt may be retried: the rules allow it, the
    /// body can be sent again, another endpoint is offered and the retry budget has room.
    fn alternative(
        &self,
        shared: Shared<'_>,
        failure: Failure,
        failed: &UpstreamEndpoint,
    ) -> Option<UpstreamEndpoint> {
        let Shared {
            target,
            template,
            payload,
        } = shared;
        let case = RetryCase {
            policy: target.retry(),
            method: HttpMethod::parse(template.method.as_str())?,
            graphql: target.graphql(),
            body: payload.kind(),
            delivery: failure.delivery,
            retries_made: 0,
        };
        if !RetryRule::allows(&case) || !payload.replayable() {
            return None;
        }
        let next = self.choose(target, Some(&endpoint_key(failed))).ok()?;
        self.registry.try_retry(target).then_some(next)
    }

    /// Records the answer of an endpoint: a 5xx response counts as a failure, any other as a good
    /// answer.
    fn settle(&self, target: &UpstreamTarget, key: &str, server_error: bool) {
        if server_error {
            self.record_error(target, key);
        } else {
            self.registry.record_success(key);
        }
    }

    /// The failure of an attempt on the endpoint `key`; a connect error counts towards the
    /// ejection of the endpoint.
    fn failed(&self, target: &UpstreamTarget, key: &str, classified: Classified) -> Failure {
        if classified.connect {
            self.record_error(target, key);
        }
        Failure {
            error: classified.error,
            delivery: classified.delivery,
        }
    }

    fn record_error(&self, target: &UpstreamTarget, key: &str) {
        let offered: Vec<String> = self
            .endpoints
            .offered(target.service())
            .iter()
            .map(endpoint_key)
            .collect();
        let rule = OutlierRule::for_threshold(target.outlier_threshold());
        self.registry.record_error(key, &rule, &offered);
    }

    /// The endpoints that a new request may go to: those that are not ejected (all of them when
    /// every one is) and, on a retry, not the endpoint `avoid` that just failed.
    fn pool(&self, target: &UpstreamTarget, avoid: Option<&str>) -> Vec<UpstreamEndpoint> {
        let offered = self.endpoints.offered(target.service());
        let now = self.registry.now_ms();
        let healthy: Vec<UpstreamEndpoint> = offered
            .iter()
            .filter(|endpoint| !self.registry.is_ejected(&endpoint_key(endpoint), now))
            .cloned()
            .collect();
        let pool = if healthy.is_empty() { offered } else { healthy };
        pool.into_iter()
            .filter(|endpoint| avoid.is_none_or(|key| endpoint_key(endpoint) != key))
            .collect()
    }

    /// The endpoint of a new request: the selector over the pool of the Service of `target`.
    fn choose(
        &self,
        target: &UpstreamTarget,
        avoid: Option<&str>,
    ) -> Result<UpstreamEndpoint, ForwardError> {
        let pool = self.pool(target, avoid);
        let counts = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let candidates: Vec<Candidate<'_>> = pool
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
            .and_then(|index| pool.into_iter().nth(index))
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

impl Template {
    /// The request of `parts` as the attempts send it: the protocol version of the upstream and no
    /// hop-by-hop headers.
    fn of(parts: Parts, target: &UpstreamTarget) -> Self {
        let mut headers = parts.headers;
        strip_hop_by_hop(&mut headers);
        Self {
            method: parts.method,
            uri: parts.uri,
            version: match target.protocol() {
                UpstreamProtocol::Http1 => Version::HTTP_11,
                UpstreamProtocol::H2c => Version::HTTP_2,
            },
            headers,
        }
    }

    /// The request for `endpoint`: its absolute target, the headers and `body`.
    fn request(
        &self,
        endpoint: &UpstreamEndpoint,
        body: ReplayBody,
    ) -> Result<axum::http::Request<ReplayBody>, ForwardError> {
        let uri = absolute(endpoint, &self.uri).ok_or(ForwardError::NoEndpoint)?;
        let mut request = axum::http::Request::builder()
            .method(self.method.clone())
            .uri(uri)
            .version(self.version)
            .body(body)
            .map_err(|_invalid| ForwardError::NoEndpoint)?;
        *request.headers_mut() = self.headers.clone();
        Ok(request)
    }
}

impl Failure {
    /// A request that never left the gateway.
    const fn unsent(error: ForwardError) -> Self {
        Self {
            error,
            delivery: Delivery::NotSent,
        }
    }
}

/// Whether the body of the request is read into memory: when the request may be retried after it
/// was sent, which takes a route with the retry policy `idempotent`, an idempotent method and, on
/// GraphQL routes, no chance of a mutation.
fn buffers(target: &UpstreamTarget, parts: &Parts) -> bool {
    HttpMethod::parse(parts.method.as_str()).is_some_and(|method| {
        RetryRule::allows(&RetryCase {
            policy: target.retry(),
            method,
            graphql: target.graphql(),
            body: RequestBody::Empty,
            delivery: Delivery::MaybeSent,
            retries_made: 0,
        })
    })
}

/// The moment the whole request must be over, `None` for a streaming route.
fn deadline_of(target: &UpstreamTarget) -> Option<Instant> {
    let limit = Duration::from_millis(u64::from(target.request_timeout_ms()?));
    Instant::now().checked_add(limit)
}

/// Runs `work` until `deadline`, when there is one; the request fails with
/// [`ForwardError::ResponseTimeout`] when it runs out.
async fn within<F: Future>(deadline: Option<Instant>, work: F) -> Result<F::Output, ForwardError> {
    match deadline {
        Some(at) => tokio::time::timeout_at(at, work)
            .await
            .map_err(|_elapsed| ForwardError::ResponseTimeout),
        None => Ok(work.await),
    }
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

/// The response of the upstream as the caller receives it: the body is relayed as it arrives,
/// under the deadline of the request, and holds the concurrency permit until it ends.
fn relayed(response: Answered, deadline: Option<Instant>, permit: Permit) -> Response {
    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, Body::new(RelayBody::new(body, deadline, permit)))
}

#[cfg(test)]
mod tests;
