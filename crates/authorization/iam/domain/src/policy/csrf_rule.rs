//! The cross-site request rule of the gateway (FR-89).

use crate::value_object::http_method::HttpMethod;

/// What the rule reads of a request.
#[derive(Debug, Clone, Copy)]
pub struct CsrfRequest<'request> {
    /// The method of the request.
    pub method: HttpMethod,
    /// Whether the request asks for a WebSocket upgrade.
    pub websocket_upgrade: bool,
    /// Whether the token of the request came from the `__Host-auth_token` cookie; a request
    /// authenticated by an `Authorization: Bearer` header is exempt.
    pub cookie_authenticated: bool,
    /// The `Origin` header.
    pub origin: Option<&'request str>,
    /// The `Referer` header, read only when `Origin` is absent.
    pub referer: Option<&'request str>,
    /// The origin of the request itself: its scheme and authority.
    pub own_origin: &'request str,
}

/// The rule that refuses an unsafe request, or a WebSocket upgrade, that rides on the cookie from
/// another site.
///
/// Such a request needs an `Origin`, or a `Referer` when `Origin` is absent, equal to the origin
/// of the request or listed in the allowed origins of the route.
#[derive(Debug, Clone, Copy)]
pub struct CsrfRule;

impl CsrfRule {
    /// Whether the request is admitted, given the allowed origins of its route.
    #[must_use]
    pub fn admits(request: &CsrfRequest<'_>, allowed_origins: &[String]) -> bool {
        if !request.cookie_authenticated
            || !(request.websocket_upgrade || is_unsafe(request.method))
        {
            return true;
        }
        let source = request.origin.map_or_else(
            || request.referer.and_then(origin_of_referer),
            |origin| Some(origin.trim()),
        );
        source.is_some_and(|source| {
            source.eq_ignore_ascii_case(request.own_origin)
                || allowed_origins.iter().any(|allowed| allowed == source)
        })
    }
}

/// A method that changes state: anything but `GET`, `HEAD` and `OPTIONS`.
const fn is_unsafe(method: HttpMethod) -> bool {
    !matches!(
        method,
        HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
    )
}

/// The scheme and authority of a `Referer` value; `None` when it has none.
fn origin_of_referer(referer: &str) -> Option<&str> {
    let referer = referer.trim();
    let (scheme, rest) = referer.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let remainder = rest.strip_prefix(authority)?;
    let origin = referer.strip_suffix(remainder)?;
    (!scheme.is_empty() && !authority.is_empty()).then_some(origin)
}

#[cfg(test)]
mod tests;
