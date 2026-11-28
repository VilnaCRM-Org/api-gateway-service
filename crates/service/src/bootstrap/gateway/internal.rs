//! The internal router, on `GATEWAY_INTERNAL_LISTEN`.
//!
//! Only `iam-control` and the gateway pods reach this listener; the admission is the network
//! policy of the deployment. `/internal/freshness` joins it with Story 9.5 (see
//! [`router_with_freshness`]) and `/internal/policy/applied` joins it in Story 13.3 (see
//! [`with_applied`]), so every other path answers the 404 problem.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use iam_application::{AppliedAnswer, AppliedPoll, AppliedQuery, FreshnessState};
use iam_domain::PolicyView;
use serde_json::{Value, json};
use shared_application::http::fallback::{method_not_allowed, not_found};
use shared_application::http::{Problem, ValidatedQuery};

/// The router of the internal listener without the freshness endpoint.
pub fn router() -> Router {
    Router::new()
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

/// `router` with `/internal/policy/applied` added (Story 13.3).
///
/// The long poll of the Sync-Fence coordinator is served whether or not the pod has bootstrapped.
pub fn with_applied(router: Router, poll: Arc<AppliedPoll>) -> Router {
    router.route("/internal/policy/applied", get(applied).with_state(poll))
}

/// `GET /internal/policy/applied?atLeast=V&offset=O&wait=T`.
///
/// 200 with the published version, the pod name and `hardBoundMs` once the pod enforces `V`, 204
/// when the wait ends first and 503 when `APPLIED_POLL_MAX_CONCURRENT` polls wait already.
async fn applied(
    State(poll): State<Arc<AppliedPoll>>,
    ValidatedQuery(query): ValidatedQuery<AppliedQuery>,
) -> Response {
    match poll.poll(query.version(), query.offset, query.wait()).await {
        AppliedAnswer::Applied { published } => Json(json!({
            "version": published.map(iam_domain::PolicyVersion::value),
            "pod": poll.pod(),
            "hardBoundMs": millis(poll.hard_bound()),
        }))
        .into_response(),
        AppliedAnswer::Unanswered => StatusCode::NO_CONTENT.into_response(),
        AppliedAnswer::Busy => Problem::new(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("The pod already holds the most applied-version polls it may.")
            .into_response(),
    }
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
