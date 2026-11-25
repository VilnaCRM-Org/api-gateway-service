//! The CORS slot and the CSRF rule of the pipeline (Story 10.12, FR-89).
//!
//! A preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) is answered after the
//! route match on the host and the path for the requested method, before authentication: 204 with
//! the CORS headers when the route's policy allows it, 403 `cors_rejected` otherwise, and it never
//! reaches the upstream. Every other response to an allowed origin carries
//! `Access-Control-Allow-Origin` with the exact origin and `Vary: Origin`.
//!
//! The CSRF rule runs right after authentication: an unsafe method or a WebSocket upgrade that the
//! `__Host-auth_token` cookie authenticated needs an `Origin`, or a `Referer`, that is the origin of
//! the request or one of the route's allowed origins (403 `csrf_rejected`). A request that carries
//! `Authorization` is exempt.

use std::sync::Arc;

use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, REFERER, UPGRADE, VARY};
use axum::http::request::Parts;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_domain::{
    CorsGrant, CorsRule, CsrfRequest, CsrfRule, HttpMethod, NormalizedPath, PolicySnapshot,
    PreflightGrant, RouteState,
};
use shared_application::http::Problem;

use super::access::Observed;
use super::headers::carries_auth_token;
use super::{Refusal, route_of};

/// The `type` of the 403 problem of a preflight that the route's CORS policy does not allow.
pub const TYPE_CORS_REJECTED: &str = "/problems/cors_rejected";

/// The `type` of the 403 problem of a cross-site request that rides on the cookie.
pub const TYPE_CSRF_REJECTED: &str = "/problems/csrf_rejected";

const REQUEST_METHOD: HeaderName = HeaderName::from_static("access-control-request-method");
const REQUEST_HEADERS: HeaderName = HeaderName::from_static("access-control-request-headers");
const ALLOW_ORIGIN: HeaderName = HeaderName::from_static("access-control-allow-origin");
const ALLOW_CREDENTIALS: HeaderName = HeaderName::from_static("access-control-allow-credentials");
const ALLOW_METHODS: HeaderName = HeaderName::from_static("access-control-allow-methods");
const ALLOW_HEADERS: HeaderName = HeaderName::from_static("access-control-allow-headers");
const MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
const EXPOSE_HEADERS: HeaderName = HeaderName::from_static("access-control-expose-headers");

/// The CORS headers of the response: only the gateway sets them, never the upstream.
const RESPONSE_HEADERS: [HeaderName; 6] = [
    ALLOW_ORIGIN,
    ALLOW_CREDENTIALS,
    ALLOW_METHODS,
    ALLOW_HEADERS,
    EXPOSE_HEADERS,
    MAX_AGE,
];

/// The value of a header that is not text: it matches no allowed value.
const UNREADABLE: &str = "\u{0}";

/// The CORS headers the response of the request gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Applied {
    /// An allowed origin on an ordinary request.
    Simple(CorsGrant),
    /// An allowed preflight.
    Preflight(PreflightGrant),
    /// A route with a CORS policy whose response gets no grant: the upstream's CORS headers are
    /// removed and the response still varies on `Origin`.
    Withheld,
}

/// Answers a preflight, when the request is one: `Ok(())` for any other request, `Err` with the
/// answer of the gateway for a preflight. The headers of an allowed one are noted in `slot`.
pub(super) fn preflight(
    snapshot: &Arc<dyn PolicySnapshot>,
    parts: &Parts,
    path: &NormalizedPath,
    seen: &mut Observed,
    slot: &mut Option<Applied>,
) -> Result<(), Refusal> {
    let Some((origin, requested)) = preflight_request(&parts.headers) else {
        return Ok(());
    };
    let method = HttpMethod::parse(requested).ok_or(Refusal::CorsRejected)?;
    let route = route_of(snapshot, parts, method, path).ok_or(Refusal::NoRoute)?;
    seen.route(snapshot, route);
    let headers = parts
        .headers
        .get(REQUEST_HEADERS)
        .map(|value| value.to_str().unwrap_or(UNREADABLE));
    let granted = CorsRule::preflight(route.fields.cors(), origin, method, headers)
        .ok_or(Refusal::CorsRejected)?;
    *slot = Some(Applied::Preflight(granted));
    Err(Refusal::Preflight)
}

/// The origin and the requested method of a preflight, `None` for any other request.
fn preflight_request(headers: &HeaderMap) -> Option<(&str, &str)> {
    let requested = headers.get(REQUEST_METHOD)?;
    let origin = headers.get(ORIGIN)?;
    Some((
        origin.to_str().unwrap_or(UNREADABLE),
        requested.to_str().unwrap_or(UNREADABLE),
    ))
}

/// Notes the CORS headers of an ordinary request from an allowed origin.
pub(super) fn simple(parts: &Parts, route: &RouteState, slot: &mut Option<Applied>) {
    let Some(policy) = route.fields.cors() else {
        return;
    };
    let granted = parts
        .headers
        .get(ORIGIN)
        .and_then(|origin| CorsRule::grant(Some(policy), origin.to_str().unwrap_or(UNREADABLE)));
    *slot = Some(granted.map_or(Applied::Withheld, Applied::Simple));
}

/// The CSRF rule for a request that has just been authenticated.
pub(super) fn csrf(parts: &Parts, method: HttpMethod, route: &RouteState) -> Result<(), Refusal> {
    let headers = &parts.headers;
    let own_origin = own_origin(parts);
    let request = CsrfRequest {
        method,
        websocket_upgrade: is_websocket_upgrade(headers),
        cookie_authenticated: !headers.contains_key(AUTHORIZATION) && carries_auth_token(headers),
        origin: text(headers, &ORIGIN),
        referer: text(headers, &REFERER),
        own_origin: &own_origin,
    };
    let allowed = route
        .fields
        .cors()
        .map_or(&[][..], |policy| policy.origins());
    if CsrfRule::admits(&request, allowed) {
        Ok(())
    } else {
        Err(Refusal::CsrfRejected)
    }
}

fn text<'headers>(headers: &'headers HeaderMap, name: &HeaderName) -> Option<&'headers str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Whether the request asks to switch to the WebSocket protocol.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim().eq_ignore_ascii_case("websocket"))
}

/// The origin of the request itself: its scheme, `https` on the TLS listeners, and the authority
/// it was sent to.
fn own_origin(parts: &Parts) -> String {
    let scheme = parts.uri.scheme_str().unwrap_or("https");
    let authority = parts
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| parts.uri.authority().map(Authority::as_str))
        .unwrap_or_default();
    format!("{scheme}://{authority}")
}

/// Puts the CORS headers of `applied` on the response. Whatever CORS headers an upstream set are
/// removed first, with or without a grant: the policy of the route is the only authority.
pub(super) fn decorate(response: &mut Response, applied: Option<&Applied>) {
    let headers = response.headers_mut();
    for name in &RESPONSE_HEADERS {
        headers.remove(name);
    }
    let (grant, preflight) = match applied {
        None => return,
        Some(Applied::Withheld) => {
            headers.append(VARY, HeaderValue::from_static("Origin"));
            return;
        }
        Some(Applied::Simple(grant)) => (grant, None),
        Some(Applied::Preflight(answer)) => (answer.grant(), Some(answer)),
    };
    drop(HeaderValue::from_str(grant.origin()).map(|origin| headers.insert(ALLOW_ORIGIN, origin)));
    if grant.allow_credentials() {
        headers.insert(ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    }
    headers.append(VARY, HeaderValue::from_static("Origin"));
    if let Some(answer) = preflight {
        set_text(headers, ALLOW_METHODS, answer.methods());
        set_text(headers, ALLOW_HEADERS, answer.headers());
        set_text(headers, MAX_AGE, &answer.max_age_seconds().to_string());
        headers.append(
            VARY,
            HeaderValue::from_static(
                "Access-Control-Request-Method, Access-Control-Request-Headers",
            ),
        );
    }
}

fn set_text(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if value.is_empty() {
        return;
    }
    drop(HeaderValue::from_str(value).map(|value| headers.insert(name, value)));
}

/// 204 without a body: the preflight is allowed, and [`decorate`] adds its headers.
pub(super) fn preflight_answer() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// 403 `cors_rejected`.
pub(super) fn cors_rejected() -> Response {
    Problem {
        r#type: TYPE_CORS_REJECTED,
        ..Problem::new(StatusCode::FORBIDDEN)
            .with_detail("The route does not allow this cross-origin request.")
    }
    .into_response()
}

/// 403 `csrf_rejected`.
pub(super) fn csrf_rejected() -> Response {
    Problem {
        r#type: TYPE_CSRF_REJECTED,
        ..Problem::new(StatusCode::FORBIDDEN)
            .with_detail("A cross-site request cannot use the session cookie.")
    }
    .into_response()
}

#[cfg(test)]
mod tests;
