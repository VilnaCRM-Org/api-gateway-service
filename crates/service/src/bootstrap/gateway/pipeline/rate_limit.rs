//! The rate-limit step of the pipeline (Story 12.2, FR-63, FR-65).
//!
//! The step follows the route match. The local per-IP flood guard decides first, for every matched
//! route; then the policies of the route that count by the client address or by the route are
//! decided in the shared store, before authentication. The policies that count by the subject are
//! decided after authentication, so a request that authentication refuses never consumes a subject
//! quota. A route without a rate policy never reaches the shared store. A request over a limit is
//! answered 429 `rate_limited` with `Retry-After`.
//!
//! The client address is the peer of the connection, which the accept loop of the public server
//! hands to the pipeline as a [`ClientAddress`] request extension.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::header::RETRY_AFTER;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_application::{Principal, RateLimitGate, RateRequest, RateStage};
use iam_domain::{
    BootClock, LocalRateLimiter, PolicySnapshot, RateDecision, RateDecisionRule, RequestDigester,
    RouteState, SubjectId, SubjectRef,
};
use iam_infrastructure::{
    BucketLocalRateLimiter, LinuxBootClock, Sha256RequestDigester, ValkeyRateLimitStore,
};
use shared_application::http::Problem;

use super::Refusal;
use crate::config::GatewayConfig;

/// The `type` of the 429 problem of a request over a rate limit.
pub const TYPE_RATE_LIMITED: &str = "/problems/rate_limited";

/// Requests per period of the per-IP flood guard: far above any policy, so only a flood from one
/// address reaches it.
const GUARD_LIMIT: u32 = 2_000;

/// The period of the flood guard.
const GUARD_PERIOD: Duration = Duration::from_secs(1);

/// The burst of the flood guard.
const GUARD_BURST: u32 = 2_000;

/// The most buckets each pool of the local limiter keeps.
const BUCKET_CAPACITY: usize = 100_000;

/// The address of the client of a connection, as the accept loop saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddress(IpAddr);

impl ClientAddress {
    /// The address of the peer.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0
    }
}

impl From<SocketAddr> for ClientAddress {
    fn from(peer: SocketAddr) -> Self {
        Self(peer.ip())
    }
}

/// The gate of production, over the Valkey at `RATE_LIMIT_STORE_URL`.
///
/// Every call of the shared store is bounded by `RATE_LIMIT_STORE_TIMEOUT`; the local limiter holds
/// the flood guard and the fallback buckets.
#[must_use]
pub fn gate_from_config(config: &GatewayConfig) -> Arc<RateLimitGate> {
    let clock: Arc<dyn BootClock> = Arc::new(LinuxBootClock);
    let guard = RateDecisionRule::new(GUARD_LIMIT, GUARD_PERIOD, GUARD_BURST);
    let local: Arc<dyn LocalRateLimiter> = Arc::new(BucketLocalRateLimiter::new(
        Arc::clone(&clock),
        guard,
        BUCKET_CAPACITY,
    ));
    let digester: Arc<dyn RequestDigester> = Arc::new(Sha256RequestDigester);
    Arc::new(RateLimitGate::new(
        Arc::new(ValkeyRateLimitStore::new(config.rate_limit.store.clone())),
        local,
        digester,
        clock,
        config.rate_limit.store_timeout,
    ))
}

/// The step before authentication: the flood guard, then the policies of the route that count
/// by the client address or the route.
pub(super) async fn before_authentication(
    gate: Option<&Arc<RateLimitGate>>,
    parts: &Parts,
    snapshot: &Arc<dyn PolicySnapshot>,
    route: &RouteState,
) -> Result<(), Refusal> {
    let Some(gate) = gate else {
        return Ok(());
    };
    let ip = client_ip(parts);
    refuse(gate.check_guard(ip.as_deref()))?;
    let request = request_of(snapshot, route, ip.as_deref(), None);
    refuse(gate.check(RateStage::Anonymous, &request).await)
}

/// The step after authentication: the policies of the route that count by the subject.
pub(super) async fn subject(
    gate: Option<&Arc<RateLimitGate>>,
    parts: &Parts,
    snapshot: &Arc<dyn PolicySnapshot>,
    route: &RouteState,
    principal: &Principal,
) -> Result<(), Refusal> {
    let Some(gate) = gate else {
        return Ok(());
    };
    let subject = subject_of(principal.subject());
    let ip = client_ip(parts);
    let request = request_of(snapshot, route, ip.as_deref(), Some(&subject));
    refuse(gate.check(RateStage::Authenticated, &request).await)
}

fn request_of<'request>(
    snapshot: &'request Arc<dyn PolicySnapshot>,
    route: &'request RouteState,
    ip: Option<&'request str>,
    subject: Option<&'request SubjectRef>,
) -> RateRequest<'request> {
    RateRequest {
        snapshot: snapshot.as_ref(),
        policies: route.fields.rate_policies(),
        route: route.id,
        ip,
        subject,
    }
}

/// The client address of the request, as text, when the accept loop recorded one.
fn client_ip(parts: &Parts) -> Option<String> {
    parts
        .extensions
        .get::<ClientAddress>()
        .map(|client| client.ip().to_string())
}

/// The subject that the token of a principal proved.
fn subject_of(subject: &SubjectId) -> SubjectRef {
    match subject {
        SubjectId::User(id) => SubjectRef::user(*id),
        SubjectId::Service(name) => SubjectRef::service(name.clone()),
    }
}

/// A rejection is the refusal 429 with the seconds to wait; an admitted request goes on.
fn refuse(decision: RateDecision) -> Result<(), Refusal> {
    decision
        .retry_after_seconds()
        .map_or(Ok(()), |seconds| Err(Refusal::RateLimited(seconds)))
}

/// The 429 problem `rate_limited` with `Retry-After: <seconds>`.
pub(super) fn rate_limited(retry_after_seconds: u64) -> Response {
    let problem = Problem {
        r#type: TYPE_RATE_LIMITED,
        ..Problem::new(StatusCode::TOO_MANY_REQUESTS)
            .with_detail("The rate limit of the route is exceeded.")
    };
    let mut response = problem.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(retry_after_seconds));
    response
}

#[cfg(test)]
mod tests;
