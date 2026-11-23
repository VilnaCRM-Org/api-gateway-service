//! The internal router, on `GATEWAY_INTERNAL_LISTEN`.
//!
//! Only `iam-control` and the gateway pods reach this listener; the admission is the network
//! policy of the deployment. `/internal/freshness` and `/internal/policy/applied` join it in
//! Stories 9.5 and 13.3, so every path answers the 404 problem for now.

use axum::Router;
use shared_application::http::fallback::{method_not_allowed, not_found};

/// The router of the internal listener.
pub fn router() -> Router {
    Router::new()
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

#[cfg(test)]
mod tests;
