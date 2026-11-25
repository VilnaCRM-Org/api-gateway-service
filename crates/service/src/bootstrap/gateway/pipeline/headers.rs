//! The header rewrite of the pipeline (Story 10.4, FR-68): what the upstream is told about the
//! caller, and what it is never told.
//!
//! Before a request is forwarded, every client-supplied `X-IAM-*`, `Forwarded` and `X-Forwarded-*`
//! header is removed, and the gateway sets `X-IAM-Subject`, `X-IAM-Subject-Kind`, `X-IAM-Session`,
//! `X-IAM-Policy-Version` and `X-Forwarded-For` from what it decided itself. `X-Request-Id` is the
//! request id of the template, which the request-id layers have already set on the request.
//!
//! `Authorization` and the `__Host-auth_token` cookie go unchanged to an upstream with
//! `forwardCredentials = true`; every other upstream gets neither, and keeps the other cookies, so
//! that an upstream that is compromised or logs headers never holds a replayable token. No
//! internal token is signed.
//!
//! Every response that passes the pipeline, the answers of the gateway itself included, carries
//! `X-IAM-Policy-Version`.

use std::net::IpAddr;

use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::Response;
use iam_application::Principal;

use super::rate_limit::ClientAddress;
use crate::http::authentication::AUTH_COOKIE;

/// The header that names the subject of the request.
pub(super) const SUBJECT_HEADER: HeaderName = HeaderName::from_static("x-iam-subject");

/// The header that names whether the subject is a `user` or a `service`.
pub(super) const SUBJECT_KIND_HEADER: HeaderName = HeaderName::from_static("x-iam-subject-kind");

/// The header that names the session of the token, when it has one.
pub(super) const SESSION_HEADER: HeaderName = HeaderName::from_static("x-iam-session");

/// The header that names the policy version the decision was made on; it is also on every
/// response.
pub(super) const POLICY_VERSION_HEADER: HeaderName =
    HeaderName::from_static("x-iam-policy-version");

/// The header that names the client address.
pub(super) const FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static("x-forwarded-for");

/// What the upstream is told about an admitted request.
#[derive(Debug)]
pub(super) struct Propagated<'principal> {
    /// The caller that the token proved.
    pub(super) principal: &'principal Principal,
    /// The version of the snapshot the decision was made on.
    pub(super) version: i64,
    /// Whether the upstream receives the credentials of the caller.
    pub(super) forward_credentials: bool,
}

/// Rewrites the headers of an admitted request for its upstream.
pub(super) fn rewrite(parts: &mut Parts, propagated: &Propagated<'_>) {
    let client = parts
        .extensions
        .get::<ClientAddress>()
        .map(|client| client.ip());
    let headers = &mut parts.headers;
    strip_client_claims(headers);
    set_principal(headers, propagated, client);
    if !propagated.forward_credentials {
        headers.remove(AUTHORIZATION);
        strip_auth_cookie(headers);
    }
}

/// Rewrites the headers of an admitted request of an anonymous route (FR-63): every client claim
/// is removed as on any route and no principal header is set, because the request has no
/// principal. The client address is still told to the upstream. The token of the request, valid or
/// not, was never read; it goes unchanged to an upstream with `forwardCredentials = true`, and an
/// upstream without it gets neither `Authorization` nor the token cookie.
pub(super) fn rewrite_anonymous(parts: &mut Parts, forward_credentials: bool) {
    let client = parts
        .extensions
        .get::<ClientAddress>()
        .map(|client| client.ip());
    let headers = &mut parts.headers;
    strip_client_claims(headers);
    if let Some(client) = client {
        set_text(headers, FORWARDED_FOR_HEADER, &client.to_string());
    }
    if !forward_credentials {
        headers.remove(AUTHORIZATION);
        strip_auth_cookie(headers);
    }
}

/// Puts `X-IAM-Policy-Version` on `response`, replacing any value the upstream sent. Without a
/// version, which means no snapshot was ever published, the response stays as it is.
pub(super) fn stamp_version(response: &mut Response, version: Option<i64>) {
    if let Some(version) = version {
        response
            .headers_mut()
            .insert(POLICY_VERSION_HEADER, HeaderValue::from(version));
    }
}

/// Removes every header with which a client could claim an identity or an address.
fn strip_client_claims(headers: &mut HeaderMap) {
    let claimed: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_claim(name.as_str()))
        .cloned()
        .collect();
    for name in claimed {
        headers.remove(name);
    }
}

fn is_claim(name: &str) -> bool {
    name.starts_with("x-iam-") || name == "forwarded" || name.starts_with("x-forwarded-")
}

fn set_principal(headers: &mut HeaderMap, propagated: &Propagated<'_>, client: Option<IpAddr>) {
    let principal = propagated.principal;
    set_text(headers, SUBJECT_HEADER, &principal.subject().to_string());
    set_text(
        headers,
        SUBJECT_KIND_HEADER,
        principal.subject_kind().as_str(),
    );
    if let Some(session) = principal.session() {
        set_text(headers, SESSION_HEADER, session.as_str());
    }
    headers.insert(POLICY_VERSION_HEADER, HeaderValue::from(propagated.version));
    if let Some(client) = client {
        set_text(headers, FORWARDED_FOR_HEADER, &client.to_string());
    }
}

/// Sets `name` to `text`. Text that is not a valid header value sets nothing, so the upstream
/// never receives a half-written identity.
fn set_text(headers: &mut HeaderMap, name: HeaderName, text: &str) {
    if let Ok(value) = HeaderValue::from_str(text) {
        headers.insert(name, value);
    }
}

/// Removes the `__Host-auth_token` cookie from the `Cookie` headers and keeps the others. A header
/// without that cookie is left byte for byte as it came.
fn strip_auth_cookie(headers: &mut HeaderMap) {
    if !headers.get_all(COOKIE).iter().any(holds_auth_cookie) {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(without_auth_cookie)
        .collect();
    headers.remove(COOKIE);
    for value in kept {
        headers.append(COOKIE, value);
    }
}

/// Whether any `Cookie` header holds a non-empty `__Host-auth_token` pair. It reads raw bytes like
/// the forwarding does, so a value with bytes outside ASCII in another pair hides nothing.
pub(super) fn carries_auth_token(headers: &HeaderMap) -> bool {
    headers.get_all(COOKIE).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b';')
            .filter(|pair| is_auth_pair(pair))
            .any(|pair| {
                pair.trim_ascii()
                    .splitn(2, |byte| *byte == b'=')
                    .nth(1)
                    .is_some_and(|token| !token.trim_ascii().is_empty())
            })
    })
}

fn holds_auth_cookie(value: &HeaderValue) -> bool {
    value
        .as_bytes()
        .split(|byte| *byte == b';')
        .any(is_auth_pair)
}

fn is_auth_pair(pair: &[u8]) -> bool {
    pair.trim_ascii()
        .split(|byte| *byte == b'=')
        .next()
        .is_some_and(|name| name == AUTH_COOKIE.as_bytes())
}

/// The cookies of `value` without the token cookie, or nothing when no other cookie is left.
fn without_auth_cookie(value: &HeaderValue) -> Option<HeaderValue> {
    if !holds_auth_cookie(value) {
        return Some(value.clone());
    }
    let kept: Vec<&[u8]> = value
        .as_bytes()
        .split(|byte| *byte == b';')
        .filter(|pair| !is_auth_pair(pair))
        .map(<[u8]>::trim_ascii)
        .filter(|pair| !pair.is_empty())
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_bytes(&kept.join(b"; ".as_slice())).ok()
}

#[cfg(test)]
mod tests;
