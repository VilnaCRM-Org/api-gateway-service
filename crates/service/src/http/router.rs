//! The assembled router: routes, fallbacks and the fixed middleware order (AD-15, AD-14).

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{get, post};
use shared_application::http::fallback::{method_not_allowed, not_found, panic_response};
use shared_application::http::middleware::request_timeout;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::config::{AppEnv, Config};
use crate::graphql::handler::{execute, explorer};
use crate::graphql::schema::ApiSchema;
use crate::http::authentication::{Authenticator, require_principal, resolve_principal};
use crate::http::docs::{docs_asset, docs_page, openapi_json};
use crate::http::ping::ping;
use crate::http::request_id::{REQUEST_ID_HEADER, sanitize_request_id};
use crate::http::{AppState, security_headers, trace};
use crate::openapi::{iam_api_router, template_api_router};

/// Builds the complete router, with `iam_routes` added to the IAM router.
///
/// It holds the REST routes, the `GraphQL` route (with the explorer in `dev` only), liveness, the
/// documentation routes and the two fallbacks, all under one middleware stack whose first layer is
/// the outermost.
///
/// Every IAM route requires a valid bearer token (`require_principal`), inside the request-id,
/// security-header and `TraceLayer` layers; the `GraphQL` route resolves the token when one is
/// present (`resolve_principal`) and refuses nothing; every other route keeps its template
/// behaviour.
pub fn assemble_with_iam_routes(
    state: AppState,
    schema: ApiSchema,
    config: &Config,
    iam_routes: Router<AppState>,
) -> Router {
    let authenticator = Authenticator::new(Arc::clone(&state.iam.query_bus));
    let (rest, _document) = template_api_router().split_for_parts();
    let (iam, _iam_document) = iam_api_router().split_for_parts();
    let iam = protect(iam.merge(iam_routes), &authenticator);
    let mut graphql = post(execute);
    if config.app_env == AppEnv::Dev {
        graphql = graphql.get(explorer);
    }
    let graphql = graphql.layer(from_fn_with_state(authenticator, resolve_principal));
    let middleware = ServiceBuilder::new()
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
        .layer(from_fn_with_state(config.request_timeout, request_timeout))
        .layer(DefaultBodyLimit::max(config.max_body_bytes));
    rest.merge(iam)
        .with_state(state)
        .route("/api/graphql", graphql.with_state(schema))
        .route("/ping", get(ping))
        .route("/api/docs", get(docs_page))
        .route("/api/docs/openapi.json", get(openapi_json))
        .route("/api/docs/{*file}", get(docs_asset))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware)
}

/// The IAM routes behind `require_principal`.
///
/// A router without routes stays as it is, because a route layer needs a route to wrap.
fn protect(iam: Router<AppState>, authenticator: &Authenticator) -> Router<AppState> {
    if iam.has_routes() {
        iam.route_layer(from_fn_with_state(authenticator.clone(), require_principal))
    } else {
        iam
    }
}

#[cfg(test)]
mod tests;
