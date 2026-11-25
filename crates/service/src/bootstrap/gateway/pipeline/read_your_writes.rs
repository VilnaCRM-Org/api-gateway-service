//! The wire side of the read-your-writes barrier (FR-14, Story 10.10): which policy version a
//! request names and the cookie that a management write response hands to the caller.
//!
//! A request names a version with `X-IAM-Min-Policy-Version: V` or with the `__Host-iam_pv`
//! cookie; the header wins. A value that is not a non-negative integer names nothing. The
//! pipeline sets the cookie on every response that carries `Iam-Policy-Version`, so that a browser
//! gets the barrier without any change of its code.

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::Response;
use iam_domain::PolicyVersion;

/// The header with which a client names the oldest policy version it accepts.
pub(super) const MIN_VERSION_HEADER: HeaderName =
    HeaderName::from_static("x-iam-min-policy-version");

/// The header with which a management write response names the version it created.
pub(super) const WRITE_VERSION_HEADER: HeaderName = HeaderName::from_static("iam-policy-version");

/// The cookie that carries the version of the last write of a browser session.
pub(super) const VERSION_COOKIE: &str = "__Host-iam_pv";

/// How long the cookie lives, in seconds.
const COOKIE_MAX_AGE_SECONDS: u32 = 60;

/// The version the request names: the header, or else the cookie.
pub(super) fn requested_version(headers: &HeaderMap) -> Option<PolicyVersion> {
    headers
        .get(&MIN_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse)
        .or_else(|| from_cookie(headers))
}

/// The version of the cookie in any `Cookie` header.
fn from_cookie(headers: &HeaderMap) -> Option<PolicyVersion> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _value)| *name == VERSION_COOKIE)
        .find_map(|(_name, value)| parse(value))
}

fn parse(raw: &str) -> Option<PolicyVersion> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse()
        .ok()
        .and_then(|value| PolicyVersion::new(value).ok())
}

/// Sets the version cookie on a response that carries `Iam-Policy-Version`; any other response
/// stays as it is.
pub(super) fn carry_version(response: &mut Response) {
    let Some(version) = response
        .headers()
        .get(&WRITE_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse)
    else {
        return;
    };
    let cookie = format!(
        "{VERSION_COOKIE}={}; Max-Age={COOKIE_MAX_AGE_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Strict",
        version.value()
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests;
