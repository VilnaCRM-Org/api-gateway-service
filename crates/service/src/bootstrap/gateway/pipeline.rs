//! The request pipeline of the public listener (FR-59, architecture section 8.1).
//!
//! Story 10.2 builds it as far as: one snapshot load and the freshness check, the route match on
//! the host, the method and the normalised path, authentication, authorization and the hand-over
//! to the [`UpstreamForwarder`] port.
//!
//! The steps run in the order of FR-59. The steps of later stories have their place in it and do
//! nothing yet: the header and connection limits of Story 10.9 come before the read-your-writes
//! barrier, the CORS slot of Story 10.12 follows the route match, the header rewrite of Story 10.4
//! comes before the forward and the access record of Story 14.1 after the response.
//!
//! The CORS slot of Story 10.12 answers a preflight after the route match and before the rate
//! limits and authentication, and marks the responses to allowed origins; the CSRF rule runs right
//! after authentication.
//!
//! The header rewrite of Story 10.4 runs just before the forward: the client's `X-IAM-*`,
//! `Forwarded` and `X-Forwarded-*` headers are removed, the principal headers are set, and the
//! credentials go only to upstreams with `forwardCredentials = true`. Every response, the answers
//! of the gateway itself included, carries `X-IAM-Policy-Version`.
//!
//! The rate-limit step of Story 12.2 follows the route match: the local per-IP guard, then the
//! policies of the route that count by address or route, before authentication, and those that
//! count by subject after it. Over a limit the answer is 429 `rate_limited` with `Retry-After`.
//!
//! The read-your-writes barrier of Story 10.10 runs before the snapshot load, only for a request
//! that names a policy version with `X-IAM-Min-Policy-Version` or the `__Host-iam_pv` cookie: a
//! version the pod has not seen is 503 `iam_propagating` at once, a version it has seen but not
//! published is waited for up to `RYW_MAX_WAIT`. A response that carries `Iam-Policy-Version` also
//! gets the `__Host-iam_pv` cookie.
//!
//! A route flagged `anonymous` (Story 10.6) skips authentication, the policies that count by
//! subject and authorization: [`RequestAuthorizer::authorize_anonymous`] allows it without a key,
//! the token is never read, and the upstream receives no principal header. The freshness check, the
//! body limit and the rate limits before authentication apply to it as to every route.
//!
//! A route flagged `streaming` (Story 11.1) registers the stream it opens in the stream registry
//! once the decision allowed it, and a subject at its stream cap is refused 429
//! `connection_limit_exceeded` before any upgrade. The forwarder relays the WebSocket upgrade or
//! the event stream under that registration, and the registry closes the stream when the policy
//! no longer allows it.
//!
//! One snapshot answers the whole request: the freshness check, the route, the revocation check and
//! the decision read the same version, and the request drops its `Arc` before it awaits the
//! forwarder (FR-13). The forwarder of production is the `HyperUpstreamForwarder` of Story 10.3:
//! a body above the limit of the route is answered 413, a refused or reset connection 502 and a
//! connect or response timeout 504.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{HOST, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::from_fn;
use axum::response::{IntoResponse as _, Response};
use iam_application::{
    Authorization, BarrierVerdict, FreshnessState, Principal, RateLimitGate, ReadYourWritesBarrier,
    RequestAuthorizer, RouteRequest, TracedAuthorization,
};
use iam_domain::{
    CallerTokenRule, Decision, DecisionReason, ForwardError, HttpMethod, NormalizedPath,
    PathNormalizer, PolicySnapshot, PolicyView, RouteHost, RouteState, TokenIdentity,
    TokenRejection, UpstreamForwarder, UpstreamTarget,
};
use iam_infrastructure::{CachingTokenRepository, SnapshotRevocationView};
use shared_application::http::Problem;
use shared_application::http::fallback::panic_response;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

use self::access::Observed;
use self::headers::Propagated;
use super::edge::framing::reject_ambiguous;
use super::listener::stale_response;
use super::streams::{StreamHandle, Streams};
use crate::http::authentication::credential;
use crate::http::request_id::{REQUEST_ID_HEADER, sanitize_request_id};

mod access;
mod connection_limit;
mod cors;
mod graphql;
mod headers;
mod rate_limit;
mod read_your_writes;
mod stream;
mod wiring;

pub use access::PipelineAccessLog;
pub use connection_limit::TYPE_CONNECTION_LIMIT;
pub use cors::{TYPE_CORS_REJECTED, TYPE_CSRF_REJECTED};
pub use rate_limit::{ClientAddress, TYPE_RATE_LIMITED, gate_from_config};
pub use wiring::{PipelineSetupError, UnauditedCommands, UnreachableUpstreams, from_config};

/// The `type` of the 400 problem of a path that breaks the path rule (FR-7).
pub const TYPE_MALFORMED_PATH: &str = "/problems/malformed_path";

/// The `type` of the 503 problem of a request that names a policy version the pod has not
/// published (FR-14).
pub const TYPE_IAM_PROPAGATING: &str = "/problems/iam_propagating";

/// The `type` of the 403 problem of a caller that lacks the key of the operation.
pub const TYPE_PERMISSION_MISSING: &str = "/problems/permission_missing";

/// The `type` of the 403 problem of an operation that the service of the route does not have.
pub const TYPE_UNKNOWN_OPERATION: &str = "/problems/unknown_operation";

/// The `type` of the 403 problem of a route whose service has no catalogue.
pub const TYPE_UNKNOWN_SERVICE: &str = "/problems/unknown_service";

/// The `type` of the 503 problem of a request on an always-audit or sensitive key whose audit
/// record the audit lane cannot take (audit-or-deny, Story 14.2).
pub const TYPE_AUDIT_UNAVAILABLE: &str = "/problems/audit_unavailable";

/// The `type` of the 503 problem of an upstream at its concurrency limit.
pub const TYPE_UPSTREAM_OVERLOADED: &str = "/problems/upstream_overloaded";

/// The forwarder the pipeline hands an authorized request to, over the types of the HTTP stack.
pub type Forwarder = dyn UpstreamForwarder<Request = Request, Response = Response>;

/// The pipeline: what a request is decided on and the port it is handed to.
#[derive(Debug, Clone)]
pub struct Pipeline {
    view: Arc<dyn PolicyView>,
    freshness: Arc<FreshnessState>,
    tokens: Arc<CachingTokenRepository>,
    authorizer: Arc<RequestAuthorizer>,
    forwarder: Arc<Forwarder>,
    barrier: Option<Arc<ReadYourWritesBarrier>>,
    rate_limits: Option<Arc<RateLimitGate>>,
    access_log: Option<Arc<PipelineAccessLog>>,
    service_callers: Option<CallerTokenRule>,
    streams: Option<Arc<Streams>>,
}

/// Why the pipeline answers a request itself, kept small until the answer is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// 503 `iam_stale`: no snapshot, or one that is not proven fresh.
    Stale,
    /// 503 `iam_propagating`: the request names a policy version that is not published yet.
    Propagating,
    /// 503 `audit_unavailable`: the request needs an audit record that the audit lane cannot take.
    AuditUnavailable,
    /// 400: the path breaks the path rule.
    MalformedPath,
    /// 400: the body is not a GraphQL request the gateway accepts (Story 10.8).
    BadRequest(&'static str),
    /// 405 with `Allow: POST`: a GraphQL route was asked with another method.
    MethodNotAllowed,
    /// 415: the body of a GraphQL request is not `application/json`.
    UnsupportedMediaType,
    /// 413: the body is above the limit of the route.
    PayloadTooLarge,
    /// 404: no route matches.
    NoRoute,
    /// 204: an allowed preflight, answered by the gateway (Story 10.12).
    Preflight,
    /// 403 `cors_rejected`: the preflight is not allowed by the route's CORS policy.
    CorsRejected,
    /// 403 `csrf_rejected`: a cross-site request that rides on the cookie.
    CsrfRejected,
    /// 429: a rate limit of the route is exceeded; the seconds to wait.
    RateLimited(u64),
    /// 429: the subject holds the most connections it may (Story 10.9).
    ConnectionLimit,
    /// 401: the token is missing or refused.
    Unauthorized,
    /// 403: the caller may not do it.
    Forbidden(DecisionReason),
    /// The forwarder returned no response.
    Failed(ForwardError),
}

impl From<Refusal> for Response {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Stale => stale(),
            Refusal::Propagating => propagating(),
            Refusal::AuditUnavailable => audit_unavailable(),
            Refusal::MalformedPath => malformed_path(),
            Refusal::BadRequest(detail) => graphql::bad_request(detail),
            Refusal::MethodNotAllowed => graphql::method_not_allowed(),
            Refusal::UnsupportedMediaType => graphql::unsupported_media_type(),
            Refusal::PayloadTooLarge => graphql::payload_too_large(),
            Refusal::NoRoute => no_route(),
            Refusal::Preflight => cors::preflight_answer(),
            Refusal::CorsRejected => cors::cors_rejected(),
            Refusal::CsrfRejected => cors::csrf_rejected(),
            Refusal::RateLimited(seconds) => rate_limit::rate_limited(seconds),
            Refusal::ConnectionLimit => connection_limit::refused(),
            Refusal::Unauthorized => unauthorized(),
            Refusal::Forbidden(reason) => forbidden(reason),
            Refusal::Failed(error) => failure(error),
        }
    }
}

impl Refusal {
    /// The reason code that the access record names for the refusal. A refused token has its own
    /// reason, which the pipeline noted when it resolved the token.
    const fn reason(self, token_refusal: Option<DecisionReason>) -> DecisionReason {
        match (self, token_refusal) {
            (Self::Stale | Self::Propagating | Self::AuditUnavailable, _) => {
                DecisionReason::Unavailable
            }
            (
                Self::MalformedPath
                | Self::BadRequest(_)
                | Self::MethodNotAllowed
                | Self::UnsupportedMediaType,
                _,
            ) => DecisionReason::MalformedOperation,
            (Self::NoRoute, _) => DecisionReason::UnknownOperation,
            (Self::CorsRejected | Self::CsrfRejected, _) => DecisionReason::PermissionMissing,
            (Self::PayloadTooLarge | Self::RateLimited(_) | Self::ConnectionLimit, _) => {
                DecisionReason::LimitsExceeded
            }
            (Self::Unauthorized, Some(reason)) | (Self::Forbidden(reason), _) => reason,
            (Self::Unauthorized, None) => DecisionReason::TokenInvalid,
            (Self::Preflight | Self::Failed(_), _) => DecisionReason::Allowed,
        }
    }
}

/// The decision and its reason that the access record names: a request that was admitted is an
/// allow, and so is one whose forwarder failed, which the status of the answer tells apart.
///
/// A request that a route in audit mode forwarded although the decision denied it is a deny with
/// the reason `audit_mode_would_deny` (FR-69).
fn verdict_of(refusal: Option<&Refusal>, seen: &Observed) -> (Decision, DecisionReason) {
    let admitted = if seen.would_deny() {
        DecisionReason::AuditModeWouldDeny
    } else {
        DecisionReason::Allowed
    };
    let reason = refusal.map_or(admitted, |refusal| refusal.reason(seen.token_refusal()));
    (reason.decision(), reason)
}

/// What a request that passed every check needs to be forwarded.
#[derive(Debug)]
struct Admitted {
    target: UpstreamTarget,
    uri: Uri,
    /// The caller the token proved; `None` on a route flagged `anonymous`, which resolves no token.
    principal: Option<Principal>,
    version: i64,
    /// The body to forward: the one the client sent, buffered on a GraphQL route.
    body: Body,
    /// The registration of the stream the request opens, on a route flagged `streaming`.
    stream: Option<Arc<StreamHandle>>,
}

/// What a request matched: its parts, its route and the request the decision reads.
#[derive(Debug, Clone, Copy)]
struct Matched<'request> {
    parts: &'request Parts,
    route: &'request RouteState,
    request: &'request RouteRequest<'request>,
}

impl Pipeline {
    /// A pipeline over the published snapshot of `view`, served while `freshness` finds the pod
    /// fresh. Tokens are resolved through `tokens`, requests are decided by `authorizer` and the
    /// authorized ones go to `forwarder`.
    #[must_use]
    pub const fn new(
        view: Arc<dyn PolicyView>,
        freshness: Arc<FreshnessState>,
        tokens: Arc<CachingTokenRepository>,
        authorizer: Arc<RequestAuthorizer>,
        forwarder: Arc<Forwarder>,
    ) -> Self {
        Self {
            view,
            freshness,
            tokens,
            authorizer,
            forwarder,
            barrier: None,
            rate_limits: None,
            access_log: None,
            service_callers: None,
            streams: None,
        }
    }

    /// The same pipeline behind the read-your-writes barrier of FR-14: a request that names a
    /// policy version is held back, or refused, until a snapshot of that version is published.
    #[must_use]
    pub fn with_read_your_writes(mut self, barrier: Arc<ReadYourWritesBarrier>) -> Self {
        self.barrier = Some(barrier);
        self
    }

    /// The same pipeline with the rate-limit step of `gate`; without one no request is limited.
    #[must_use]
    pub fn with_rate_limits(mut self, gate: Arc<RateLimitGate>) -> Self {
        self.rate_limits = Some(gate);
        self
    }

    /// The same pipeline with the access record of Story 14.1 after the response: one record per
    /// request, never waiting and never changing the answer.
    #[must_use]
    pub fn with_access_log(mut self, access_log: Arc<PipelineAccessLog>) -> Self {
        if let Some(gate) = access_log.audit_gate() {
            self.authorizer.install_audit_gate(gate);
        }
        self.access_log = Some(access_log);
        self
    }

    /// The same pipeline for the east-west listener (Story 10.13, FR-90): a `ROLE_SERVICE` token
    /// must also carry the caller audience of `rule` and live no longer than its service lifetime,
    /// or the request is answered 401; a user's token passes unchanged.
    #[must_use]
    pub fn with_service_callers(mut self, rule: CallerTokenRule) -> Self {
        self.service_callers = Some(rule);
        self
    }

    /// The same pipeline with the streams of Story 11.1: a route flagged `streaming` registers the
    /// stream it opens, and the registry decides it again with the rule of this pipeline.
    #[must_use]
    pub fn with_streams(mut self, streams: Arc<Streams>) -> Self {
        streams.install(Arc::new(stream::PipelineRedecision::new(
            Arc::clone(&self.view),
            Arc::clone(&self.authorizer),
            streams.clock(),
        )));
        self.streams = Some(streams);
        self
    }

    async fn handle(&self, request: Request) -> Response {
        let (mut parts, body) = request.into_parts();
        let started = self
            .access_log
            .is_some()
            .then(|| PipelineAccessLog::begin(&parts));
        let mut seen = Observed::default();
        let mut cors = None;
        let admitted = self.admit(&parts, body, &mut seen, &mut cors).await;
        let verdict = verdict_of(admitted.as_ref().err(), &seen);
        let mut response = match admitted {
            Ok(admitted) => {
                parts.uri = admitted.uri;
                let forward_credentials = admitted.target.forward_credentials();
                match admitted.principal.as_ref() {
                    Some(principal) => headers::rewrite(
                        &mut parts,
                        &Propagated {
                            principal,
                            version: admitted.version,
                            forward_credentials,
                        },
                    ),
                    None => headers::rewrite_anonymous(&mut parts, forward_credentials),
                }
                stream::attach(&mut parts, admitted.stream);
                self.forward(admitted.target, Request::from_parts(parts, admitted.body))
                    .await
            }
            Err(refusal) => refusal.into(),
        };
        cors::decorate(&mut response, cors.as_ref());
        read_your_writes::carry_version(&mut response);
        headers::stamp_version(&mut response, self.response_version(&seen));
        if let (Some(log), Some(started)) = (self.access_log.as_ref(), started) {
            log.finish(started, seen, verdict, &response);
        }
        response
    }

    /// Step 2 of the pipeline: a request that names a policy version waits for it before the
    /// snapshot is loaded. Without a version nothing is read but the headers.
    async fn await_version(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let Some(barrier) = self.barrier.as_ref() else {
            return Ok(());
        };
        let Some(minimum) = read_your_writes::requested_version(headers) else {
            return Ok(());
        };
        match barrier.admit(minimum).await {
            BarrierVerdict::Proceed => Ok(()),
            BarrierVerdict::Propagating => Err(Refusal::Propagating),
        }
    }

    /// Steps 3 to 8 of the pipeline: the snapshot is loaded here and dropped when this returns, so
    /// nothing of it is held while the forwarder runs.
    async fn admit(
        &self,
        parts: &Parts,
        body: Body,
        seen: &mut Observed,
        cors: &mut Option<cors::Applied>,
    ) -> Result<Admitted, Refusal> {
        self.await_version(&parts.headers).await?;
        let snapshot = self.snapshot(seen).ok_or(Refusal::Stale)?;
        seen.snapshot(&snapshot);
        let method = HttpMethod::parse(parts.method.as_str()).ok_or(Refusal::NoRoute)?;
        let path =
            PathNormalizer::normalize(parts.uri.path()).map_err(|_rule| Refusal::MalformedPath)?;
        cors::preflight(&snapshot, parts, &path, seen, cors)?;
        graphql_posts_only(&snapshot, parts, method, &path, seen)?;
        let route = route_of(&snapshot, parts, method, &path).ok_or(Refusal::NoRoute)?;
        seen.route(&snapshot, route);
        cors::simple(parts, route, cors);
        rate_limit::before_authentication(self.rate_limits.as_ref(), parts, &snapshot, route)
            .await?;
        let request = RouteRequest {
            snapshot: &snapshot,
            service: route.fields.service(),
            enforcement: route.fields.enforcement(),
            method,
            path: &path,
            request_id: request_id_of(&parts.headers),
        };
        let matched = Matched {
            parts,
            route,
            request: &request,
        };
        let (principal, body) = self.principal_and_body(&matched, body, seen).await?;
        self.assemble(&matched, &path, (principal, body), seen)
    }

    /// What the forwarder needs: the target of the route, the URI that was authorized and, on a
    /// route flagged `streaming`, the registration of the stream (Story 11.1).
    fn assemble(
        &self,
        matched: &Matched<'_>,
        path: &NormalizedPath,
        (principal, body): (Option<Principal>, Body),
        seen: &Observed,
    ) -> Result<Admitted, Refusal> {
        let Matched {
            parts,
            route,
            request,
        } = *matched;
        let snapshot = request.snapshot;
        let upstream = snapshot
            .upstream_by_id(route.fields.upstream_id())
            .ok_or(Refusal::Failed(ForwardError::NoEndpoint))?;
        let stream = stream::register(
            self.streams.as_ref(),
            &stream::Opening {
                parts,
                route,
                snapshot,
                principal: principal.as_ref(),
                key: seen.required_key(),
            },
        )?;
        Ok(Admitted {
            target: target_of(upstream, route),
            uri: forwarded_uri(path, upstream_query(route.fields.flags().graphql(), parts))
                .ok_or(Refusal::MalformedPath)?,
            principal,
            version: snapshot.version().value(),
            body,
            stream,
        })
    }

    /// The principal of the request and the body to forward: a GraphQL route that needs a token
    /// buffers and authorizes its body, every other route leaves it untouched.
    async fn principal_and_body(
        &self,
        matched: &Matched<'_>,
        body: Body,
        seen: &mut Observed,
    ) -> Result<(Option<Principal>, Body), Refusal> {
        let flags = matched.route.fields.flags();
        if flags.graphql() && !flags.anonymous() {
            return graphql::identify(self, matched, body, seen).await;
        }
        let principal = self
            .identify(matched.parts, matched.route, matched.request, seen)
            .await?;
        Ok((principal, body))
    }

    /// Steps 5 to 7 of the pipeline for a matched route: authentication, the policies that count by
    /// subject and authorization. A route flagged `anonymous` skips all three (FR-63): the token,
    /// valid or not, is never read, and the request has no principal. The freshness check before
    /// the route match, the body limit of the forwarder and the rate limits before authentication
    /// apply to it as to every other route.
    async fn identify(
        &self,
        parts: &Parts,
        route: &RouteState,
        request: &RouteRequest<'_>,
        seen: &mut Observed,
    ) -> Result<Option<Principal>, Refusal> {
        if route.fields.flags().anonymous() {
            let TracedAuthorization {
                authorization,
                trace,
                denied,
                audit_slot,
            } = RequestAuthorizer::authorize_anonymous(request);
            seen.decision(trace, denied);
            seen.hold_audit_slot(audit_slot);
            permitted(authorization)?;
            if forwards_credentials(request.snapshot, route) {
                cors::csrf(parts, request.method, route)?;
            }
            return Ok(None);
        }
        let principal = self.authenticate(request.snapshot, parts, seen).await?;
        cors::csrf(parts, request.method, route)?;
        rate_limit::subject(
            self.rate_limits.as_ref(),
            parts,
            request.snapshot,
            route,
            &principal,
        )
        .await?;
        self.authorize(request, &principal, seen).await?;
        Ok(Some(principal))
    }

    /// The version that every response names: the one of the snapshot the request was decided on,
    /// or the published one when the request ended before a snapshot was loaded.
    fn response_version(&self, seen: &Observed) -> Option<i64> {
        seen.answer_version(|| {
            self.view
                .current()
                .map(|snapshot| snapshot.version().value())
        })
    }

    /// The snapshot of this request: the published one, while the pod is proven fresh. The view is
    /// asked exactly once, whatever the answer of the freshness check.
    fn snapshot(&self, seen: &mut Observed) -> Option<Arc<dyn PolicySnapshot>> {
        let current = self.view.current();
        seen.published(current.as_ref().map(|snapshot| snapshot.version().value()));
        let snapshot = current?;
        self.freshness.is_fresh().then_some(snapshot)
    }

    async fn authenticate(
        &self,
        snapshot: &Arc<dyn PolicySnapshot>,
        parts: &Parts,
        seen: &mut Observed,
    ) -> Result<Principal, Refusal> {
        let revocations = SnapshotRevocationView::over(Arc::clone(snapshot));
        let resolved = self
            .tokens
            .resolve_with(&revocations, &credential(&parts.headers))
            .await
            .and_then(|identity| self.check_caller(identity));
        seen.token(&resolved);
        let principal = principal_of(resolved)?;
        connection_limit::claim(parts, &principal)?;
        Ok(principal)
    }

    /// The caller rule of the east-west listener over a resolved identity; the public listener has
    /// none.
    fn check_caller(&self, identity: TokenIdentity) -> Result<TokenIdentity, TokenRejection> {
        match self.service_callers.as_ref() {
            Some(rule) => rule.check(&identity).map(|()| identity),
            None => Ok(identity),
        }
    }

    async fn authorize(
        &self,
        request: &RouteRequest<'_>,
        principal: &Principal,
        seen: &mut Observed,
    ) -> Result<(), Refusal> {
        let traced = self.authorizer.authorize_traced(request, principal).await;
        let TracedAuthorization {
            authorization,
            trace,
            denied,
            audit_slot,
        } = traced;
        seen.decision(trace, denied);
        seen.audit_mode(matches!(authorization, Authorization::WouldDeny(_)));
        seen.hold_audit_slot(audit_slot);
        permitted(authorization)
    }

    async fn forward(&self, target: UpstreamTarget, request: Request) -> Response {
        answer(self.forwarder.forward(target, request).await)
    }
}

/// A request that uses another method than `POST` on the path of a GraphQL route is refused 405,
/// whatever other route the method and the path would match: an operation never travels in a URL.
fn graphql_posts_only(
    snapshot: &Arc<dyn PolicySnapshot>,
    parts: &Parts,
    method: HttpMethod,
    path: &NormalizedPath,
    seen: &mut Observed,
) -> Result<(), Refusal> {
    graphql::post_route(snapshot, parts, method, path).map_or(Ok(()), |route| {
        seen.route(snapshot, route);
        Err(Refusal::MethodNotAllowed)
    })
}

/// The principal of a resolved token: a token that cannot be checked is a stale pod, any other
/// rejection is a 401.
fn principal_of(resolved: Result<TokenIdentity, TokenRejection>) -> Result<Principal, Refusal> {
    match resolved {
        Ok(identity) => Ok(Principal::from(identity)),
        Err(TokenRejection::Unavailable) => Err(Refusal::Stale),
        Err(_refused) => Err(Refusal::Unauthorized),
    }
}

/// What the decision of the authorizer means for the request.
const fn permitted(authorization: Authorization) -> Result<(), Refusal> {
    match authorization {
        Authorization::Allowed(_version) => Ok(()),
        Authorization::Denied(reason) => Err(Refusal::Forbidden(reason)),
        Authorization::WouldDeny(_reason) => Ok(()),
        Authorization::Unavailable => Err(Refusal::Stale),
        Authorization::AuditUnavailable => Err(Refusal::AuditUnavailable),
    }
}

/// The answer of the gateway: the response of the upstream, or the failure of the forwarder.
fn answer(forwarded: Result<Response, ForwardError>) -> Response {
    forwarded.unwrap_or_else(failure)
}

/// The router of the public listener: every request goes through the [`Pipeline`].
///
/// The pipeline sits inside the request-id layers and the guard that answers a panic of a request
/// task with 500. A request whose length or path is ambiguous is answered 400 first (Story 10.9).
pub fn router(pipeline: Pipeline) -> Router {
    Router::new().fallback(serve).with_state(pipeline).layer(
        ServiceBuilder::new()
            .layer(from_fn(reject_ambiguous))
            .layer(from_fn(sanitize_request_id))
            .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
            .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
            .layer(CatchPanicLayer::custom(panic_response)),
    )
}

async fn serve(State(pipeline): State<Pipeline>, request: Request) -> Response {
    pipeline.handle(request).await
}

/// The route of the request: the host without its port, the method and the canonical path.
fn route_of<'snapshot>(
    snapshot: &'snapshot Arc<dyn PolicySnapshot>,
    parts: &Parts,
    method: HttpMethod,
    path: &NormalizedPath,
) -> Option<&'snapshot RouteState> {
    route_for_host(snapshot, &host_of(parts)?, method, path)
}

/// The route of a host that is already in lower case and has no port, a method and a canonical
/// path.
fn route_for_host<'snapshot>(
    snapshot: &'snapshot Arc<dyn PolicySnapshot>,
    host: &str,
    method: HttpMethod,
    path: &NormalizedPath,
) -> Option<&'snapshot RouteState> {
    let host = RouteHost::new(host).ok()?;
    snapshot.route(&host, method, path.canonical().as_str())
}

/// The host of the request in lower case, without a port.
fn host_of(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| parts.uri.authority().map(Authority::as_str))?;
    let host = value
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(value, |(host, _port)| host);
    Some(host.to_ascii_lowercase())
}

fn request_id_of(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// Where the request of `route` goes and how it is delivered: the Service, protocol and timeouts
/// of its upstream, and the body limit, flags, retry policy and request timeout of the route.
/// Whether the upstream of the route gets the client's credentials, so that an anonymous route
/// that forwards the auth cookie needs the CSRF rule as an authenticated one does.
fn forwards_credentials(snapshot: &Arc<dyn PolicySnapshot>, route: &RouteState) -> bool {
    snapshot
        .upstream_by_id(route.fields.upstream_id())
        .is_some_and(|upstream| upstream.settings.forward_credentials())
}

fn target_of(upstream: &iam_domain::UpstreamState, route: &RouteState) -> UpstreamTarget {
    UpstreamTarget::new(upstream.name.clone(), route.id)
        .with_settings(&upstream.settings)
        .with_route(&route.fields)
}

/// The query string the upstream receives: none on a GraphQL route, whose operations travel in the
/// body only. Upstream frameworks normalise parameter names (leading spaces, `query[]`, `.`), so no
/// refusal list can tell which spelling an upstream would read as an operation; nothing is forwarded.
fn upstream_query(graphql: bool, parts: &Parts) -> Option<&str> {
    if graphql { None } else { parts.uri.query() }
}

/// The target of the upstream request: the canonical re-encoded path, so that the single decoding
/// of the upstream yields the bytes that were authorized, and the query as it came.
fn forwarded_uri(path: &NormalizedPath, query: Option<&str>) -> Option<Uri> {
    let canonical = path.canonical();
    let target = query.map_or_else(
        || canonical.as_str().to_owned(),
        |query| format!("{}?{query}", canonical.as_str()),
    );
    target.parse().ok()
}

fn stale() -> Response {
    stale_response("The policy snapshot is not proven fresh.")
}

/// 503 `iam_propagating` with `Retry-After: 1`.
fn propagating() -> Response {
    let problem = Problem {
        r#type: TYPE_IAM_PROPAGATING,
        ..Problem::new(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("The policy version the request names is not published here yet.")
    };
    let mut response = problem.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// 503 `audit_unavailable` with `Retry-After: 1`: the audit lane cannot take the record of the
/// request, so the request does not run.
fn audit_unavailable() -> Response {
    let problem = Problem {
        r#type: TYPE_AUDIT_UNAVAILABLE,
        ..Problem::new(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("The audit record of this request cannot be stored right now.")
    };
    let mut response = problem.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn malformed_path() -> Response {
    Problem {
        r#type: TYPE_MALFORMED_PATH,
        ..Problem::new(StatusCode::BAD_REQUEST).with_detail("The request path is not valid.")
    }
    .into_response()
}

fn no_route() -> Response {
    Problem::new(StatusCode::NOT_FOUND)
        .with_detail("No route matches the request.")
        .into_response()
}

fn unauthorized() -> Response {
    Problem::new(StatusCode::UNAUTHORIZED)
        .with_detail("A valid bearer token is required.")
        .into_response()
}

/// The 403 problem of a refusal. Its `type` is the reason code of the decision, which belongs to
/// the service of the route and names no operation of another one.
fn forbidden(reason: DecisionReason) -> Response {
    Problem {
        r#type: denial_type(reason),
        ..Problem::new(StatusCode::FORBIDDEN).with_detail("The caller may not do this.")
    }
    .into_response()
}

const fn denial_type(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::UnknownOperation => TYPE_UNKNOWN_OPERATION,
        DecisionReason::UnknownService => TYPE_UNKNOWN_SERVICE,
        DecisionReason::Allowed
        | DecisionReason::TokenMissing
        | DecisionReason::TokenInvalid
        | DecisionReason::TokenExpired
        | DecisionReason::TokenRevoked
        | DecisionReason::MalformedOperation
        | DecisionReason::PermissionMissing
        | DecisionReason::ScopeMissing
        | DecisionReason::LimitsExceeded
        | DecisionReason::Unavailable
        | DecisionReason::AuditModeWouldDeny => TYPE_PERMISSION_MISSING,
    }
}

/// The answer of the gateway when the forwarder returns no response.
fn failure(error: ForwardError) -> Response {
    match error {
        ForwardError::ConnectTimeout | ForwardError::ResponseTimeout => {
            Problem::new(StatusCode::GATEWAY_TIMEOUT).into_response()
        }
        ForwardError::BodyTooLarge => Problem::new(StatusCode::PAYLOAD_TOO_LARGE)
            .with_detail("The request body is above the limit of the route.")
            .into_response(),
        ForwardError::Overloaded => Problem {
            r#type: TYPE_UPSTREAM_OVERLOADED,
            ..Problem::new(StatusCode::SERVICE_UNAVAILABLE)
        }
        .into_response(),
        ForwardError::NotSent | ForwardError::NoEndpoint | ForwardError::Upstream => {
            Problem::new(StatusCode::BAD_GATEWAY).into_response()
        }
    }
}

#[cfg(test)]
mod tests;
