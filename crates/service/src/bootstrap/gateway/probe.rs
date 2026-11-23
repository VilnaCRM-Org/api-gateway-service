//! The probe router, on `GATEWAY_PROBE_LISTEN`.
//!
//! `/ping` answers while the process runs and touches no dependency (FR-54). `/internal/startup`,
//! `/internal/ready`, `/internal/drain` and `/metrics` join it in Stories 9.7, 15.2 and 16.2.

use axum::Router;
use axum::routing::get;
use shared_application::http::fallback::{method_not_allowed, not_found};

use crate::http::ping::ping;

/// The router of the probe listener.
pub fn router() -> Router {
    Router::new()
        .route("/ping", get(ping))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

#[cfg(test)]
mod tests;
