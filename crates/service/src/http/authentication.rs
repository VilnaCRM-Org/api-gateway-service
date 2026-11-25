//! Authentication of the callers of IAM's own API (FR-3).
//!
//! The bearer token is read from `Authorization: Bearer` or, when that header is absent, from the
//! `__Host-auth_token` cookie, and resolved through [`ResolveTokenQuery`]: memoized verification,
//! the revocation check and the caller rule of service principals. [`require_principal`] guards the
//! IAM routes and answers a missing or refused token with the 401 problem and
//! `WWW-Authenticate: Bearer`; [`resolve_principal`] only resolves, for the GraphQL route, whose
//! IAM fields check the principal themselves. Neither writes the token to a span or a log line.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use iam_application::{Principal, ResolveTokenQuery};
use iam_domain::Credential;
use shared_application::http::Problem;
use shared_domain::QueryBus;

/// The cookie that carries the token of a browser session; the gateway forwards it only to
/// `iam-control` (FR-68) and checks its cross-site use (FR-89).
pub const AUTH_COOKIE: &str = "__Host-auth_token";

/// The authentication scheme of the challenge of a 401 answer.
const BEARER: &str = "Bearer";

/// Resolves the credential of a request to the [`Principal`] it proves.
#[derive(Debug, Clone)]
pub struct Authenticator {
    query_bus: Arc<dyn QueryBus>,
}

impl Authenticator {
    /// An authenticator that asks `query_bus`, where [`ResolveTokenQuery`] is registered.
    #[must_use]
    pub const fn new(query_bus: Arc<dyn QueryBus>) -> Self {
        Self { query_bus }
    }

    /// The principal of the credential of `headers`.
    ///
    /// # Errors
    ///
    /// The problem of the refusal: 401 for a missing or refused token, 500 when the revocation
    /// state cannot be read.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, Problem> {
        let query = ResolveTokenQuery {
            credential: credential(headers),
        };
        self.query_bus.ask(query).await.map_err(Problem::from)
    }
}

/// Lets a request through only with a valid token, its [`Principal`] in the request extensions.
pub async fn require_principal(
    State(authenticator): State<Authenticator>,
    mut request: Request,
    next: Next,
) -> Response {
    let outcome = authenticator.authenticate(request.headers()).await;
    match outcome {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(problem) => refusal(problem),
    }
}

/// Puts the [`Principal`] of a valid token into the request extensions and lets every request
/// through.
///
/// A request without a token is not resolved at all.
pub async fn resolve_principal(
    State(authenticator): State<Authenticator>,
    mut request: Request,
    next: Next,
) -> Response {
    let principal = if credential(request.headers()).is_blank() {
        None
    } else {
        authenticator.authenticate(request.headers()).await.ok()
    };
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }
    next.run(request).await
}

/// The problem response, with the `Bearer` challenge when the token was missing or refused.
fn refusal(problem: Problem) -> Response {
    let challenge = problem.status == StatusCode::UNAUTHORIZED.as_u16();
    let mut response = problem.into_response();
    if challenge {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static(BEARER));
    }
    response
}

/// The token of `Authorization: Bearer`, or of the cookie when that header is absent.
///
/// It is blank when the request carries none or an `Authorization` header of another scheme.
pub(crate) fn credential(headers: &HeaderMap) -> Credential {
    let raw = headers
        .get(AUTHORIZATION)
        .map_or_else(|| cookie(headers), bearer);
    Credential::new(raw.unwrap_or_default().to_owned())
}

/// The token of an `Authorization` value of the `Bearer` scheme.
fn bearer(value: &HeaderValue) -> Option<&str> {
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    scheme.eq_ignore_ascii_case(BEARER).then(|| token.trim())
}

/// The value of the [`AUTH_COOKIE`] cookie in any `Cookie` header.
pub(crate) fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == AUTH_COOKIE).then_some(value)
        })
}

#[cfg(test)]
mod tests;
