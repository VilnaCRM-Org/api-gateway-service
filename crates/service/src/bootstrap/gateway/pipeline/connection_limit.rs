//! The per-subject connection limit of the pipeline (Story 10.9, NFR-21).
//!
//! The subject of a token is known only after authentication, so the limit is claimed here: the
//! serve loop hands each connection an `Arc<SubjectClaims>` as a request extension, and the first
//! request that proves a subject claims one of the subject's slots for the connection. A subject
//! that already holds the most connections it may is refused with 429 `connection_limit_exceeded`.
//! A request without the extension (the mesh listener in process, a unit test) is never limited.

use std::sync::Arc;

use axum::http::header::RETRY_AFTER;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_application::Principal;
use shared_application::http::Problem;

use super::Refusal;
use crate::bootstrap::gateway::edge::SubjectClaims;

/// The `type` of the 429 problem of a subject at its connection limit.
pub const TYPE_CONNECTION_LIMIT: &str = "/problems/connection_limit_exceeded";

/// Claims a slot of the subject of `principal` for the connection of the request.
pub(super) fn claim(parts: &Parts, principal: &Principal) -> Result<(), Refusal> {
    let Some(claims) = parts.extensions.get::<Arc<SubjectClaims>>() else {
        return Ok(());
    };
    if claims.claim(&principal.subject().to_string()) {
        Ok(())
    } else {
        Err(Refusal::ConnectionLimit)
    }
}

/// The 429 problem `connection_limit_exceeded` with `Retry-After: 1`.
pub(super) fn refused() -> Response {
    let problem = Problem {
        r#type: TYPE_CONNECTION_LIMIT,
        ..Problem::new(StatusCode::TOO_MANY_REQUESTS)
            .with_detail("The subject holds the most connections it may.")
    };
    let mut response = problem.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
mod tests;
