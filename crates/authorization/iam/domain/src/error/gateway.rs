//! Domain errors of the gateway configuration: upstreams, routes and rate policies.

use crate::error::{InvalidIamValue, VersionConflict};
use crate::value_object::identifier::RouteId;

/// A value that breaks an invariant of the `Upstream` aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidUpstream {
    /// The name is empty or longer than 63 characters.
    #[error("This value must contain between 1 and 63 characters.")]
    NameLength,
    /// The name does not match `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`.
    #[error("This value must be a lower-case service name such as user-service.")]
    NamePattern,
    /// The Kubernetes namespace is not a DNS label.
    #[error("This value must be a lower-case DNS label of at most 63 characters.")]
    NamespaceFormat,
    /// The Kubernetes Service name is not a DNS label.
    #[error("This value must be a lower-case DNS label of at most 63 characters.")]
    ServiceFormat,
    /// The catalogue service name is empty or longer than 63 characters.
    #[error("This value must contain between 1 and 63 characters.")]
    CatalogServiceLength,
    /// The catalogue service name does not match the service-name pattern.
    #[error("This value must be a lower-case service name such as user-service.")]
    CatalogServicePattern,
    /// The port is outside 1 to 65,535.
    #[error("This value must be between 1 and 65535.")]
    PortRange,
    /// The connect timeout is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295 milliseconds.")]
    ConnectTimeoutRange,
    /// The response timeout is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295 milliseconds.")]
    ResponseTimeoutRange,
    /// The concurrency limit is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295.")]
    ConcurrencyLimitRange,
    /// The retry budget is above 100 percent or negative.
    #[error("This value must be between 0 and 100.")]
    RetryBudgetRange,
    /// The outlier threshold is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295.")]
    OutlierThresholdRange,
}

impl InvalidUpstream {
    /// The property that carries the invalid value.
    #[must_use]
    pub const fn property_path(self) -> &'static str {
        match self {
            Self::NameLength | Self::NamePattern => "name",
            Self::NamespaceFormat => "namespace",
            Self::ServiceFormat => "serviceName",
            Self::CatalogServiceLength | Self::CatalogServicePattern => "catalogService",
            Self::PortRange => "port",
            Self::ConnectTimeoutRange => "connectTimeoutMs",
            Self::ResponseTimeoutRange => "responseTimeoutMs",
            Self::ConcurrencyLimitRange => "concurrencyLimit",
            Self::RetryBudgetRange => "retryBudgetPercent",
            Self::OutlierThresholdRange => "outlierThreshold",
        }
    }

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NameLength | Self::CatalogServiceLength => "length",
            Self::NamePattern | Self::CatalogServicePattern => "pattern",
            Self::NamespaceFormat | Self::ServiceFormat => "format",
            Self::PortRange
            | Self::ConnectTimeoutRange
            | Self::ResponseTimeoutRange
            | Self::ConcurrencyLimitRange
            | Self::RetryBudgetRange
            | Self::OutlierThresholdRange => "range",
        }
    }
}

/// A value that breaks an invariant of the `Route` aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRoute {
    /// The host is empty or longer than 253 characters.
    #[error("This value must contain between 1 and 253 characters.")]
    HostLength,
    /// The host is not a lower-case DNS name.
    #[error("This value must be a lower-case DNS name.")]
    HostFormat,
    /// The route names no method.
    #[error("This collection must contain at least 1 method.")]
    MethodsRequired,
    /// The path pattern does not start with a slash.
    #[error("This value must start with /.")]
    PathPrefix,
    /// The path pattern is too long or malformed.
    #[error(
        "This value must be a path of at most 2048 characters with {{name}} and {{name:*}} segments."
    )]
    PathFormat,
    /// The service name is empty or longer than 63 characters.
    #[error("This value must contain between 1 and 63 characters.")]
    ServiceLength,
    /// The service name does not match the service-name pattern.
    #[error("This value must be a lower-case service name such as user-service.")]
    ServicePattern,
    /// The body limit is zero or negative.
    #[error("This value must be 1 byte or more.")]
    BodyLimitRange,
    /// The request timeout is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295 milliseconds.")]
    RequestTimeoutRange,
    /// The idle timeout is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295 milliseconds.")]
    IdleTimeoutRange,
    /// The route names more than 10 rate policies.
    #[error("This collection must contain 10 elements or fewer.")]
    RatePolicyCount,
    /// The route names a rate policy twice.
    #[error("This collection must not contain a rate policy twice.")]
    RatePolicyDuplicate,
    /// The CORS policy names no origin.
    #[error("This collection must contain at least 1 origin.")]
    CorsOriginRequired,
    /// A CORS origin is not an exact `http` or `https` origin.
    #[error("This value must be an exact origin such as https://app.example.com.")]
    CorsOriginFormat,
    /// A CORS header name is not an HTTP token.
    #[error("This value must be an HTTP header name.")]
    CorsHeaderFormat,
    /// The CORS max age is negative or above 86,400 seconds.
    #[error("This value must be between 0 and 86400 seconds.")]
    CorsMaxAgeRange,
}

impl InvalidRoute {
    /// The property that carries the invalid value.
    #[must_use]
    pub const fn property_path(self) -> &'static str {
        match self {
            Self::HostLength | Self::HostFormat => "host",
            Self::MethodsRequired => "methods",
            Self::PathPrefix | Self::PathFormat => "pathPattern",
            Self::ServiceLength | Self::ServicePattern => "service",
            Self::BodyLimitRange => "bodyLimit",
            Self::RequestTimeoutRange => "timeouts.requestMs",
            Self::IdleTimeoutRange => "timeouts.idleMs",
            Self::RatePolicyCount | Self::RatePolicyDuplicate => "ratePolicies",
            Self::CorsOriginRequired | Self::CorsOriginFormat => "cors.origins",
            Self::CorsHeaderFormat => "cors.headers",
            Self::CorsMaxAgeRange => "cors.maxAgeSeconds",
        }
    }

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::HostLength | Self::ServiceLength => "length",
            Self::HostFormat
            | Self::PathFormat
            | Self::CorsOriginFormat
            | Self::CorsHeaderFormat => "format",
            Self::MethodsRequired | Self::CorsOriginRequired => "required",
            Self::PathPrefix => "prefix",
            Self::ServicePattern => "pattern",
            Self::BodyLimitRange
            | Self::RequestTimeoutRange
            | Self::IdleTimeoutRange
            | Self::CorsMaxAgeRange => "range",
            Self::RatePolicyCount => "count",
            Self::RatePolicyDuplicate => "duplicate",
        }
    }
}

/// A value that breaks an invariant of the `RatePolicy` aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRatePolicy {
    /// The name has fewer than 1 or more than 100 characters.
    #[error("This value must contain between 1 and 100 characters.")]
    NameLength,
    /// The name holds a control character.
    #[error("This value must not contain a control character.")]
    NameControlCharacter,
    /// The limit is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295.")]
    LimitRange,
    /// The period is zero or does not fit 32 bits.
    #[error("This value must be between 1 and 4294967295 seconds.")]
    PeriodRange,
    /// The burst is negative or does not fit 32 bits.
    #[error("This value must be between 0 and 4294967295.")]
    BurstRange,
}

impl InvalidRatePolicy {
    /// The property that carries the invalid value.
    #[must_use]
    pub const fn property_path(self) -> &'static str {
        match self {
            Self::NameLength | Self::NameControlCharacter => "name",
            Self::LimitRange => "limit",
            Self::PeriodRange => "periodSeconds",
            Self::BurstRange => "burst",
        }
    }

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NameLength => "length",
            Self::NameControlCharacter => "control_character",
            Self::LimitRange | Self::PeriodRange | Self::BurstRange => "range",
        }
    }
}

/// A change of an upstream, a route or a rate policy that the aggregate refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigChangeRefused {
    /// The entry is deleted; the application answers 404.
    #[error("The entry was deleted.")]
    Deleted,
    /// The change names no version or a stale one; the application answers 428 or 412.
    #[error(transparent)]
    Version(#[from] VersionConflict),
    /// The version of the entry cannot be increased any more.
    #[error(transparent)]
    Range(#[from] InvalidIamValue),
}

impl ConfigChangeRefused {
    /// The machine-readable refusal code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Version(conflict) => conflict.code(),
            Self::Range(invalid) => invalid.code(),
        }
    }
}

/// An update of an upstream that the aggregate refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamChangeRefused {
    /// The update names another name than the stored one: upstream names are immutable.
    #[error("The name of an upstream cannot be changed.")]
    Renamed,
    /// The upstream is deleted or the version does not match.
    #[error(transparent)]
    Refused(#[from] ConfigChangeRefused),
}

impl UpstreamChangeRefused {
    /// The machine-readable refusal code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Renamed => "renamed",
            Self::Refused(refused) => refused.code(),
        }
    }
}

/// Two routes of one host conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteConflict {
    /// The routes have the same pattern and share a method.
    #[error("Routes {first} and {second} have the same host and path pattern and share a method.")]
    SamePattern {
        /// One route.
        first: RouteId,
        /// The other route.
        second: RouteId,
    },
    /// An anonymous route has a broader pattern than a protected route and would shadow it.
    #[error(
        "The anonymous route {anonymous} has a broader pattern than the protected route {protected}."
    )]
    AnonymousShadow {
        /// The anonymous route.
        anonymous: RouteId,
        /// The protected route.
        protected: RouteId,
    },
}

impl RouteConflict {
    /// The machine-readable conflict code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SamePattern { .. } => "same_pattern",
            Self::AnonymousShadow { .. } => "anonymous_shadow",
        }
    }
}

/// An upstream or a rate policy that a route still references cannot be deleted; the application
/// answers 409.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{count} route(s) still reference this entry.")]
pub struct ReferencedByRoute {
    /// The number of routes that reference the entry.
    pub count: u64,
}

impl ReferencedByRoute {
    /// The machine-readable refusal code.
    pub const CODE: &'static str = "referenced_by_route";

    /// Lets a deletion through when no route references the entry.
    ///
    /// # Errors
    ///
    /// [`ReferencedByRoute`] when `count` is above zero.
    pub const fn check(count: u64) -> Result<(), Self> {
        if count == 0 {
            Ok(())
        } else {
            Err(Self { count })
        }
    }
}

#[cfg(test)]
mod tests;
