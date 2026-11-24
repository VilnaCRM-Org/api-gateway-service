//! The internal router, on `GATEWAY_INTERNAL_LISTEN`.
//!
//! Only `iam-control` and the gateway pods reach this listener; the admission is the network
//! policy of the deployment. `/internal/freshness` joins it with Story 9.5 (see
//! [`router_with_freshness`]) and `/internal/policy/applied` joins it in Story 13.3, so every
//! other path answers the 404 problem.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use iam_application::FreshnessState;
use iam_domain::PolicyView;
use serde_json::{Value, json};
use shared_application::http::fallback::{method_not_allowed, not_found};

/// The router of the internal listener without the freshness endpoint.
pub fn router() -> Router {
    Router::new()
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

/// What `/internal/freshness` reads.
#[derive(Debug, Clone)]
struct Freshness {
    state: Arc<FreshnessState>,
    view: Arc<dyn PolicyView>,
}

/// The router of the internal listener with `/internal/freshness`: the published version, the age
/// of the proof, the digest and the configured `FRESHNESS_HARD_BOUND` as `hardBoundMs`.
pub fn router_with_freshness(state: Arc<FreshnessState>, view: Arc<dyn PolicyView>) -> Router {
    Router::new()
        .route("/internal/freshness", get(freshness))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(Freshness { state, view })
}

/// The report of `/internal/freshness`. `version` and `digest` are `null` before a snapshot is
/// published, `proofAgeMs` is `null` while the pod holds no proof.
async fn freshness(State(freshness): State<Freshness>) -> Json<Value> {
    let snapshot = freshness.view.current();
    let reading = freshness.state.reading();
    Json(json!({
        "version": snapshot.as_ref().map(|snapshot| snapshot.version().value()),
        "digest": snapshot.as_ref().map(|snapshot| snapshot.digest().to_hex()),
        "proofAgeMs": reading.proof_age.map(millis),
        "hardBoundMs": millis(freshness.state.rule().hard_bound()),
        "fresh": reading.verdict.is_fresh(),
    }))
}

/// The milliseconds of `duration`, saturating at the largest number.
fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
