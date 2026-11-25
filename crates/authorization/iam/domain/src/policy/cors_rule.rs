//! The CORS decisions of a route (FR-89): the answer to a preflight and the headers of a response
//! to an allowed origin.

use crate::route::cors::CorsPolicy;
use crate::value_object::http_method::HttpMethod;

/// The grant of an allowed origin: the exact origin and whether credentials are allowed with it.
///
/// The origin is always the exact one of the request, never `*`, so a grant with credentials never
/// pairs the wildcard with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsGrant {
    origin: String,
    allow_credentials: bool,
}

impl CorsGrant {
    /// The value of `Access-Control-Allow-Origin`: the exact origin of the request.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Whether `Access-Control-Allow-Credentials: true` is sent.
    #[must_use]
    pub const fn allow_credentials(&self) -> bool {
        self.allow_credentials
    }
}

/// The answer to an allowed preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightGrant {
    grant: CorsGrant,
    methods: String,
    headers: String,
    max_age_seconds: u32,
}

impl PreflightGrant {
    /// The grant of the origin.
    #[must_use]
    pub const fn grant(&self) -> &CorsGrant {
        &self.grant
    }

    /// The value of `Access-Control-Allow-Methods`: the methods of the policy.
    #[must_use]
    pub fn methods(&self) -> &str {
        &self.methods
    }

    /// The value of `Access-Control-Allow-Headers`: the headers of the policy.
    #[must_use]
    pub fn headers(&self) -> &str {
        &self.headers
    }

    /// The value of `Access-Control-Max-Age`, in seconds.
    #[must_use]
    pub const fn max_age_seconds(&self) -> u32 {
        self.max_age_seconds
    }
}

/// The CORS decisions over the [`CorsPolicy`] of a route.
#[derive(Debug, Clone, Copy)]
pub struct CorsRule;

impl CorsRule {
    /// The grant of `origin` under the policy of the route: `None` when the route has no policy
    /// or the origin is not one of its exact origins.
    #[must_use]
    pub fn grant(policy: Option<&CorsPolicy>, origin: &str) -> Option<CorsGrant> {
        let policy = policy?;
        policy
            .origins()
            .iter()
            .any(|allowed| allowed == origin)
            .then(|| CorsGrant {
                origin: origin.to_owned(),
                allow_credentials: policy.allow_credentials(),
            })
    }

    /// The answer to a preflight from `origin` that asks for `method` and the comma-separated
    /// `request_headers`: `None` (a rejection) when the route has no policy, the origin is not
    /// allowed, the method is not one of the policy or a requested header is not listed. Header
    /// names compare without regard to case.
    #[must_use]
    pub fn preflight(
        policy: Option<&CorsPolicy>,
        origin: &str,
        method: HttpMethod,
        request_headers: Option<&str>,
    ) -> Option<PreflightGrant> {
        let policy = policy?;
        let grant = Self::grant(Some(policy), origin)?;
        let method_allowed = policy.methods().contains(&method);
        let headers_allowed = request_headers.is_none_or(|requested| {
            requested
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .all(|name| {
                    policy
                        .headers()
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(name))
                })
        });
        (method_allowed && headers_allowed).then(|| PreflightGrant {
            grant,
            methods: policy
                .methods()
                .iter()
                .map(|allowed| allowed.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            headers: policy.headers().join(", "),
            max_age_seconds: policy.max_age_seconds(),
        })
    }
}

#[cfg(test)]
mod tests;
