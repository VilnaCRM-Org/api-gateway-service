//! The decision listener of the gateway, on `GATEWAY_DECISION_LISTEN` (Story 10.11, FR-6, FR-11,
//! FR-19, architecture section 8.9).
//!
//! Microservices that check their own internal actions call `POST /api/access-validations`,
//! `POST /api/access-validations/batch`, `POST /api/token-resolutions` and `POST /api/graphql`
//! here. The listener serves the handlers and DTOs of `iam-control`, so the contract is one, with
//! the decision path of FR-6 fed from the replicated snapshot instead of PostgreSQL: the caller is
//! authenticated with `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`, the caller rule
//! of FR-12 is evaluated from the snapshot, the subject's token is resolved with the memo and the
//! revocation sets of the snapshot, and the required keys come from the catalogues of the snapshot.
//! The GraphQL schema exposes only `validateAccess`, `validateAccessBatch` and `resolveToken`, and
//! the listener serves nothing else: any other path is the 404 problem.
//!
//! A snapshot that is not proven fresh makes every read fail, which the decision path turns into
//! the deny `unavailable` (FR-13); it never decides on a stale snapshot. The gateway keeps no audit
//! log yet, so the refusals of the caller rule are discarded.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_graphql::{EmptyMutation, EmptySubscription, Schema};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::post;
use axum::{Extension, Json, Router};
use iam_application::graphql::{DecisionQuery, IamAuthorizationExtension};
use iam_application::http::{IamState, STALE_BATCH_VALIDATION_PATH, STALE_VALIDATION_PATH};
use iam_application::{
    AccessDecisionService, FreshPolicyView, FreshnessState, GatewayValidateAccessBatchQueryHandler,
    GatewayValidateAccessQueryHandler, IamAccessGuard, Principal, ReadYourWritesBarrier,
    RecordRejectedAttemptCommandHandler, ResolveSubjectTokenQueryHandler, ResolveTokenQueryHandler,
    ServiceCatalogLoader, SnapshotPolicyReads,
};
use iam_domain::{
    AccessTokenVerifier, AttemptSummary, PolicyReadRepository, PolicyView, RejectedAttempt,
    RejectedAttemptLog, RevocationView, TokenMemo, TokenRepository,
};
use iam_infrastructure::{
    CachingTokenRepository, JwtAccessTokenVerifier, JwtKeyFileError, MokaTokenMemo,
    Sha256RequestDigester, SnapshotRevocationView,
};
use serde_json::{Map, Value};
use shared_application::http::fallback::{method_not_allowed, not_found, panic_response};
use shared_application::http::middleware::request_timeout;
use shared_application::http::{ApiJson, Problem};
use shared_domain::{Clock, CommandBus, QueryBus};
use shared_infrastructure::bus::{DuplicateHandler, InMemoryCommandBus, InMemoryQueryBus};
use shared_infrastructure::id::UuidV7Generator;
use tower::{ServiceBuilder, ServiceExt as _};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use utoipa_axum::router::OpenApiRouter;

use crate::bootstrap::KEY_FILE_POLL_INTERVAL;
use crate::config::GatewayConfig;
use crate::graphql::handler::graphql_request;
use crate::graphql::schema::{MAX_QUERY_COMPLEXITY, MAX_QUERY_DEPTH};
use crate::http::authentication::{Authenticator, require_principal, resolve_principal};
use crate::http::authorization::require_operation;
use crate::http::request_id::{REQUEST_ID_HEADER, sanitize_request_id};
use crate::http::router::GRAPHQL_BODY_LIMIT_BYTES;
use crate::http::{security_headers, trace};

/// The longest a decision request may take before the 503 problem answers it.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The body limit of a single check; the batch route and the GraphQL route have their own.
pub const BODY_LIMIT_BYTES: usize = 64 * 1024;

/// The schema of the decision listener: the three decision fields, no mutation, no subscription.
pub type DecisionSchema = Schema<DecisionQuery, EmptyMutation, EmptySubscription>;

/// The decision listener cannot be set up.
#[derive(Debug, thiserror::Error)]
pub enum DecisionSetupError {
    /// The key file of the token verifier cannot be read or parsed.
    #[error(transparent)]
    Keys(#[from] JwtKeyFileError),
    /// A message has two handlers.
    #[error(transparent)]
    Handlers(#[from] DuplicateHandler),
}

/// What the decision listener reads: the published snapshot, the proof that it is fresh and the
/// clock.
#[derive(Debug, Clone)]
pub struct DecisionPorts {
    /// The published snapshot.
    pub view: Arc<dyn PolicyView>,
    /// The proof of freshness of the pod.
    pub freshness: Arc<FreshnessState>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
}

/// The buses, the guard and the authenticator over the snapshot.
struct Wiring {
    reads: Arc<SnapshotPolicyReads>,
    state: IamState,
    guard: Arc<IamAccessGuard>,
    authenticator: Authenticator,
}

/// Refusals of the caller rule are not recorded: the gateway has no audit log before Story 11.
#[derive(Debug)]
struct DiscardedRejections;

impl RejectedAttemptLog for DiscardedRejections {
    fn offer(&self, _attempt: RejectedAttempt) {}

    fn drain(&self, _now: SystemTime) -> Vec<AttemptSummary> {
        Vec::new()
    }

    fn requeue(&self, _summaries: Vec<AttemptSummary>) {}
}

/// The router of the decision listener.
///
/// # Errors
///
/// [`DecisionSetupError::Keys`] when `JWT_PUBLIC_KEYS_FILE` holds no valid key set, and
/// [`DecisionSetupError::Handlers`] when a message has two handlers.
pub fn router(config: &GatewayConfig, ports: DecisionPorts) -> Result<Router, DecisionSetupError> {
    build(config, ports, None)
}

/// The router of the decision listener with the read-your-writes barrier of FR-14.
///
/// The barrier acts on `minPolicyVersion`: a version above the highest the pod has seen, or one
/// that is not published within the wait of `barrier`, is the deny `unavailable`.
///
/// # Errors
///
/// [`DecisionSetupError::Keys`] when `JWT_PUBLIC_KEYS_FILE` holds no valid key set, and
/// [`DecisionSetupError::Handlers`] when a message has two handlers.
pub fn router_with_barrier(
    config: &GatewayConfig,
    ports: DecisionPorts,
    barrier: &Arc<ReadYourWritesBarrier>,
) -> Result<Router, DecisionSetupError> {
    build(config, ports, Some(barrier))
}

fn build(
    config: &GatewayConfig,
    ports: DecisionPorts,
    barrier: Option<&Arc<ReadYourWritesBarrier>>,
) -> Result<Router, DecisionSetupError> {
    let wiring = wire(config, ports, barrier)?;
    let rest = OpenApiRouter::<IamState>::new()
        .nest("/api", iam_application::http::decision_router())
        .split_for_parts()
        .0
        .route_layer(from_fn_with_state(
            Arc::clone(&wiring.guard),
            require_operation,
        ))
        .route_layer(from_fn_with_state(
            wiring.authenticator.clone(),
            require_principal,
        ))
        .with_state(wiring.state.clone())
        .layer(from_fn_with_state(stale_gate(&wiring), answer_stale));
    let schema = decision_schema(&wiring);
    let graphql = post(execute).layer(
        ServiceBuilder::new()
            .layer(DefaultBodyLimit::max(GRAPHQL_BODY_LIMIT_BYTES))
            .layer(from_fn_with_state(wiring.authenticator, resolve_principal)),
    );
    let routed = rest
        .route("/api/graphql", graphql.with_state(schema))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);
    Ok(with_middleware(routed))
}

/// What the dispatch of a stale pod needs: the freshness check and the router that decides the
/// access validations without authenticating their callers.
#[derive(Clone)]
struct StaleGate {
    reads: Arc<SnapshotPolicyReads>,
    stale: Router,
}

fn stale_gate(wiring: &Wiring) -> StaleGate {
    StaleGate {
        reads: Arc::clone(&wiring.reads),
        stale: iam_application::http::stale_decision_router().with_state(wiring.state.clone()),
    }
}

/// While the snapshot is not proven fresh, the access validations skip the authentication of their
/// callers, which cannot be decided without the snapshot, and get the deny `unavailable` for every
/// check (FR-13): the decision API always answers with a decision body. Everything else, and every
/// request on a fresh pod, takes the normal route.
async fn answer_stale(State(gate): State<StaleGate>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let validation = request.method() == Method::POST
        && (path == STALE_VALIDATION_PATH || path == STALE_BATCH_VALIDATION_PATH);
    if validation && gate.reads.serving().is_err() {
        let Ok(response) = gate.stale.oneshot(request).await;
        return response;
    }
    next.run(request).await
}

/// The buses, the guard and the authenticator over the snapshot of `ports`.
fn wire(
    config: &GatewayConfig,
    ports: DecisionPorts,
    barrier: Option<&Arc<ReadYourWritesBarrier>>,
) -> Result<Wiring, DecisionSetupError> {
    let DecisionPorts {
        view,
        freshness,
        clock,
    } = ports;
    let tokens = token_repository(config, &view, &freshness, &clock)?;
    let reads = Arc::new(SnapshotPolicyReads::new(view, freshness));
    let policy: Arc<dyn PolicyReadRepository> = Arc::<SnapshotPolicyReads>::clone(&reads);
    let decisions = Arc::new(AccessDecisionService::new(
        Arc::clone(&tokens),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::clone(&clock),
        Arc::new(UuidV7Generator),
    ));
    let commands: Arc<dyn CommandBus> = Arc::new(rejection_commands(&clock)?);
    let queries: Arc<dyn QueryBus> =
        Arc::new(query_bus(config, &decisions, (&reads, &tokens), barrier)?);
    let guard = Arc::new(IamAccessGuard::new(
        Arc::clone(&decisions),
        Arc::clone(&commands),
    ));
    let state = IamState {
        command_bus: commands,
        query_bus: Arc::clone(&queries),
        uuid_generator: Arc::new(UuidV7Generator),
        clock,
        request_digester: Arc::new(Sha256RequestDigester),
    };
    Ok(Wiring {
        reads,
        state,
        guard,
        authenticator: Authenticator::new(queries),
    })
}

/// The token repository: the memoised verification of `JWT_PUBLIC_KEYS_FILE` and the revocation
/// sets of the snapshot, which fail while the snapshot is not proven fresh.
fn token_repository(
    config: &GatewayConfig,
    view: &Arc<dyn PolicyView>,
    freshness: &Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
) -> Result<Arc<dyn TokenRepository>, DecisionSetupError> {
    let tokens = &config.tokens;
    let verifier = Arc::new(JwtAccessTokenVerifier::from_file(
        &tokens.public_keys_file,
        &tokens.jwt,
        Arc::clone(clock),
    )?);
    drop(verifier.watch(KEY_FILE_POLL_INTERVAL));
    let verifier: Arc<dyn AccessTokenVerifier> = verifier;
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(tokens.memo, Arc::clone(clock)));
    let fresh: Arc<dyn PolicyView> = Arc::new(FreshPolicyView::new(
        Arc::clone(view),
        Arc::clone(freshness),
    ));
    let revocations: Arc<dyn RevocationView> = Arc::new(SnapshotRevocationView::new(fresh));
    Ok(Arc::new(CachingTokenRepository::new(
        verifier,
        memo,
        revocations,
    )))
}

fn rejection_commands(clock: &Arc<dyn Clock>) -> Result<InMemoryCommandBus, DecisionSetupError> {
    register_rejections(InMemoryCommandBus::new(), clock)
}

/// Registers the handler that discards the refusals of the caller rule on `bus`.
fn register_rejections(
    bus: InMemoryCommandBus,
    clock: &Arc<dyn Clock>,
) -> Result<InMemoryCommandBus, DecisionSetupError> {
    let log: Arc<dyn RejectedAttemptLog> = Arc::new(DiscardedRejections);
    let handler = RecordRejectedAttemptCommandHandler::new(log, Arc::clone(clock));
    Ok(bus.register(handler)?)
}

/// The query bus of the decision listener: the authentication of callers, token resolution and the
/// two access validations over the snapshot.
fn query_bus(
    config: &GatewayConfig,
    decisions: &Arc<AccessDecisionService>,
    (reads, tokens): (&Arc<SnapshotPolicyReads>, &Arc<dyn TokenRepository>),
    barrier: Option<&Arc<ReadYourWritesBarrier>>,
) -> Result<InMemoryQueryBus, DecisionSetupError> {
    let authenticate =
        ResolveTokenQueryHandler::new(Arc::clone(tokens), config.tokens.callers.clone());
    let resolve = ResolveSubjectTokenQueryHandler::new(Arc::clone(tokens));
    let mut validate =
        GatewayValidateAccessQueryHandler::new(Arc::clone(decisions), Arc::clone(reads));
    let mut batch = GatewayValidateAccessBatchQueryHandler::new(
        Arc::clone(decisions),
        Arc::clone(reads),
        Arc::clone(tokens),
    );
    if let Some(barrier) = barrier {
        validate = validate.with_barrier(Arc::clone(barrier));
        batch = batch.with_barrier(Arc::clone(barrier));
    }
    Ok(InMemoryQueryBus::new()
        .register(authenticate)?
        .register(resolve)?
        .register(validate)?
        .register(batch)?)
}

/// The schema over the state of the decision listener, with the caller rule of FR-12 on every
/// document.
fn decision_schema(wiring: &Wiring) -> DecisionSchema {
    Schema::build(DecisionQuery, EmptyMutation, EmptySubscription)
        .limit_depth(MAX_QUERY_DEPTH)
        .limit_complexity(MAX_QUERY_COMPLEXITY)
        .data(wiring.state.clone())
        .extension(IamAuthorizationExtension::new(Arc::clone(&wiring.guard)))
        .finish()
}

/// Executes one GraphQL operation of the decision schema; the principal is the caller that the
/// authentication layer resolved, if any.
async fn execute(
    State(schema): State<DecisionSchema>,
    principal: Option<Extension<Principal>>,
    ApiJson(body): ApiJson<Map<String, Value>>,
) -> Result<Json<async_graphql::Response>, Problem> {
    let principal = principal.map(|Extension(principal)| principal);
    let request = graphql_request(body, principal).ok_or_else(|| {
        Problem::new(StatusCode::UNPROCESSABLE_ENTITY)
            .with_detail("The request body is not a GraphQL request.")
    })?;
    Ok(Json(schema.execute(request).await))
}

/// `routes` under the layers of the listener, outermost first: request identifier, security
/// headers, trace, panic guard, timeout and the default body limit.
fn with_middleware(routes: Router) -> Router {
    routes.layer(
        ServiceBuilder::new()
            .layer(from_fn(sanitize_request_id))
            .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
            .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
            .layer(security_headers::layer())
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::make_span)
                    .on_response(trace::on_response)
                    .on_failure(()),
            )
            .layer(CatchPanicLayer::custom(panic_response))
            .layer(from_fn_with_state(REQUEST_TIMEOUT, request_timeout))
            .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES)),
    )
}

#[cfg(test)]
mod tests;
