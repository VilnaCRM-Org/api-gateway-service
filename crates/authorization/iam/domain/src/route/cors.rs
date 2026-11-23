//! The CORS policy of a route.

use crate::error::InvalidRoute;
use crate::value_object::http_method::HttpMethod;

/// The largest `maxAgeSeconds` of a CORS policy: one day.
const MAX_AGE_SECONDS: i64 = 86_400;

/// The unvalidated values of a CORS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsDraft {
    /// The allowed origins, each exact.
    pub origins: Vec<String>,
    /// The allowed methods.
    pub methods: Vec<HttpMethod>,
    /// The allowed request headers.
    pub headers: Vec<String>,
    /// Whether credentials are allowed.
    pub allow_credentials: bool,
    /// How long a preflight answer may be cached, in seconds.
    pub max_age_seconds: i64,
}

/// A CORS policy: exact origins (no wildcard), methods, headers, `allowCredentials` and a
/// `maxAgeSeconds` of at most 86,400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsPolicy {
    origins: Vec<String>,
    methods: Vec<HttpMethod>,
    headers: Vec<String>,
    allow_credentials: bool,
    max_age_seconds: u32,
}

impl CorsPolicy {
    /// Validates the draft.
    ///
    /// # Errors
    ///
    /// Every violation, in the order origins, headers, max age: [`InvalidRoute::CorsOriginRequired`],
    /// [`InvalidRoute::CorsOriginFormat`], [`InvalidRoute::CorsHeaderFormat`] and
    /// [`InvalidRoute::CorsMaxAgeRange`].
    pub fn new(draft: CorsDraft) -> Result<Self, Vec<InvalidRoute>> {
        let violations = Self::violations(&draft);
        match u32::try_from(draft.max_age_seconds) {
            Ok(max_age_seconds) if violations.is_empty() => Ok(Self {
                origins: draft.origins,
                methods: draft.methods,
                headers: draft.headers,
                allow_credentials: draft.allow_credentials,
                max_age_seconds,
            }),
            _ => Err(violations),
        }
    }

    /// The violations of the draft, in the order origins, headers, max age.
    fn violations(draft: &CorsDraft) -> Vec<InvalidRoute> {
        let origins = if draft.origins.is_empty() {
            Some(InvalidRoute::CorsOriginRequired)
        } else {
            (!draft.origins.iter().all(|origin| is_exact_origin(origin)))
                .then_some(InvalidRoute::CorsOriginFormat)
        };
        let headers = (!draft.headers.iter().all(|header| is_token(header)))
            .then_some(InvalidRoute::CorsHeaderFormat);
        let max_age = (!(0..=MAX_AGE_SECONDS).contains(&draft.max_age_seconds))
            .then_some(InvalidRoute::CorsMaxAgeRange);
        [origins, headers, max_age].into_iter().flatten().collect()
    }

    /// The allowed origins.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// The allowed methods.
    #[must_use]
    pub fn methods(&self) -> &[HttpMethod] {
        &self.methods
    }

    /// The allowed request headers.
    #[must_use]
    pub fn headers(&self) -> &[String] {
        &self.headers
    }

    /// Whether credentials are allowed.
    #[must_use]
    pub const fn allow_credentials(&self) -> bool {
        self.allow_credentials
    }

    /// How long a preflight answer may be cached, in seconds.
    #[must_use]
    pub const fn max_age_seconds(&self) -> u32 {
        self.max_age_seconds
    }
}

/// `http://` or `https://` and a non-empty authority of visible characters without a path, a
/// query, a wildcard or a space.
fn is_exact_origin(value: &str) -> bool {
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    authority.is_some_and(|authority| {
        !authority.is_empty()
            && authority.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'[' | b']')
            })
    })
}

/// An HTTP token: visible ASCII without separators.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

#[cfg(test)]
mod tests;
