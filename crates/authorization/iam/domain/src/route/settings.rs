//! The settings of a route that are small value objects: flags, enforcement, limits, timeouts and
//! the retry policy.

use crate::error::InvalidRoute;

/// One flag of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteFlag {
    /// The route serves GraphQL.
    Graphql,
    /// The route streams its response.
    Streaming,
    /// The route is served without authentication.
    Anonymous,
}

impl RouteFlag {
    /// The name of the flag in changed-field lists.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graphql => "graphql",
            Self::Streaming => "streaming",
            Self::Anonymous => "anonymous",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Graphql => 0b001,
            Self::Streaming => 0b010,
            Self::Anonymous => 0b100,
        }
    }
}

/// The flags `graphql`, `streaming` and `anonymous` of a route, all off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteFlags(u8);

impl RouteFlags {
    /// The flags with `flag` switched on or off.
    #[must_use]
    pub const fn with(self, flag: RouteFlag, on: bool) -> Self {
        if on {
            Self(self.0 | flag.bit())
        } else {
            Self(self.0 & !flag.bit())
        }
    }

    /// Whether `flag` is on.
    #[must_use]
    pub const fn has(self, flag: RouteFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    /// Whether the route serves GraphQL.
    #[must_use]
    pub const fn graphql(self) -> bool {
        self.has(RouteFlag::Graphql)
    }

    /// Whether the route streams its response.
    #[must_use]
    pub const fn streaming(self) -> bool {
        self.has(RouteFlag::Streaming)
    }

    /// Whether the route is served without authentication.
    #[must_use]
    pub const fn anonymous(self) -> bool {
        self.has(RouteFlag::Anonymous)
    }
}

/// What the gateway does with a request that the decision denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// A denied request is refused.
    Enforce,
    /// A denied request is let through and audited.
    Audit,
}

impl EnforcementMode {
    /// The name of the mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Audit => "audit",
        }
    }
}

/// Which failed requests the gateway retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    /// Nothing is retried.
    None,
    /// Idempotent requests are retried.
    Idempotent,
}

impl RetryPolicy {
    /// The name of the policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Idempotent => "idempotent",
        }
    }
}

/// The largest request body a route accepts, in bytes; at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimit(u64);

impl BodyLimit {
    /// Validates the number of bytes.
    ///
    /// # Errors
    ///
    /// [`InvalidRoute::BodyLimitRange`] when the value is zero or negative.
    pub fn new(bytes: i64) -> Result<Self, InvalidRoute> {
        u64::try_from(bytes)
            .ok()
            .filter(|bytes| *bytes > 0)
            .map(Self)
            .ok_or(InvalidRoute::BodyLimitRange)
    }

    /// The number of bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// The request and the idle timeout of a route, in milliseconds; both at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteTimeouts {
    request_ms: u32,
    idle_ms: u32,
}

impl RouteTimeouts {
    /// Validates both timeouts.
    ///
    /// # Errors
    ///
    /// Every violation, in the order request then idle: [`InvalidRoute::RequestTimeoutRange`] and
    /// [`InvalidRoute::IdleTimeoutRange`] for a value that is zero, negative or above 32 bits.
    pub fn new(request_ms: i64, idle_ms: i64) -> Result<Self, Vec<InvalidRoute>> {
        match (positive(request_ms), positive(idle_ms)) {
            (Some(request_ms), Some(idle_ms)) => Ok(Self {
                request_ms,
                idle_ms,
            }),
            (request, idle) => Err([
                request
                    .is_none()
                    .then_some(InvalidRoute::RequestTimeoutRange),
                idle.is_none().then_some(InvalidRoute::IdleTimeoutRange),
            ]
            .into_iter()
            .flatten()
            .collect()),
        }
    }

    /// The request timeout in milliseconds.
    #[must_use]
    pub const fn request_ms(self) -> u32 {
        self.request_ms
    }

    /// The idle timeout in milliseconds.
    #[must_use]
    pub const fn idle_ms(self) -> u32 {
        self.idle_ms
    }
}

/// The value when it is between 1 and `u32::MAX`.
fn positive(value: i64) -> Option<u32> {
    u32::try_from(value).ok().filter(|value| *value > 0)
}

#[cfg(test)]
mod tests;
