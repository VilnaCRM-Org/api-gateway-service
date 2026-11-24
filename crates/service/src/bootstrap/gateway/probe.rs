//! The probe router, on `GATEWAY_PROBE_LISTEN`.
//!
//! `/ping` answers while the process runs and touches no dependency (FR-54). With the probes of
//! Story 9.7 ([`router_with_probes`]) it is the liveness probe of the tokio watchdog, and
//! `/internal/startup` and `/internal/ready` join it, each answering 200, or 503 with a problem
//! document that names the condition that does not hold. `/internal/drain` and `/metrics` join in
//! Stories 15.2 and 16.2.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use iam_application::PodProbes;
use shared_application::http::Problem;
use shared_application::http::fallback::{method_not_allowed, not_found};

use crate::http::ping::ping;

/// The router of the probe listener without the probes of the pod: `/ping` answers while the
/// process runs.
pub fn router() -> Router {
    Router::new()
        .route("/ping", get(ping))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

/// The router of the probe listener over `probes`: liveness on `/ping`, startup on
/// `/internal/startup` and readiness on `/internal/ready`.
pub fn router_with_probes(probes: Arc<PodProbes>) -> Router {
    Router::new()
        .route("/ping", get(live))
        .route("/internal/startup", get(started))
        .route("/internal/ready", get(ready))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(probes)
}

/// 503 with a problem document whose detail says what does not hold.
fn unavailable(detail: String) -> Response {
    Problem::new(StatusCode::SERVICE_UNAVAILABLE)
        .with_detail(detail)
        .into_response()
}

async fn live(State(probes): State<Arc<PodProbes>>) -> Response {
    if probes.live() {
        ping().await.into_response()
    } else {
        unavailable("The watchdog has not ticked for 10 seconds.".to_owned())
    }
}

async fn started(State(probes): State<Arc<PodProbes>>) -> Response {
    probes.startup().map_or_else(
        |reason| unavailable(reason.to_string()),
        |()| "started".into_response(),
    )
}

async fn ready(State(probes): State<Arc<PodProbes>>) -> Response {
    probes.ready().map_or_else(
        |reason| unavailable(reason.to_string()),
        |()| "ready".into_response(),
    )
}

#[cfg(test)]
mod tests;
