//! The reserved `iam:` permission keys that authorize IAM's own operations.

use crate::error::InvalidPermissionKey;
use crate::value_object::service_name::ServiceName;

/// The service segment of a reserved key: one service, or `*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceScope {
    /// `*`: every service the family's rule admits.
    All,
    /// One service.
    Service(ServiceName),
}

impl ServiceScope {
    /// The named service; `None` for `*`.
    #[must_use]
    pub const fn service(&self) -> Option<&ServiceName> {
        match self {
            Self::All => None,
            Self::Service(service) => Some(service),
        }
    }

    fn parse(value: &str) -> Result<Self, InvalidPermissionKey> {
        if value == "*" {
            return Ok(Self::All);
        }
        ServiceName::new(value)
            .map(Self::Service)
            .map_err(|_error| InvalidPermissionKey::Service)
    }
}

impl std::fmt::Display for ServiceScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Service(service) => std::fmt::Display::fmt(service, f),
        }
    }
}

/// Exactly the reserved keys; `iam:cache:flush` does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReservedPermission {
    /// `iam:validate:{service}` or `iam:validate:*`.
    Validate(ServiceScope),
    /// `iam:grant:{service}` or `iam:grant:*` (every service, `iam` included).
    Grant(ServiceScope),
    /// `iam:grant:sensitive`.
    GrantSensitive,
    /// `iam:grant:wildcard`.
    GrantWildcard,
    /// `iam:spec:{service}` or `iam:spec:*` (every service except `iam`).
    Spec(ServiceScope),
    /// `iam:audit:read`.
    AuditRead,
    /// `iam:revoke:sessions`.
    RevokeSessions,
    /// `iam:revoke:global`.
    RevokeGlobal,
    /// `iam:policy:resync`.
    PolicyResync,
    /// `iam:route:anonymous`.
    RouteAnonymous,
    /// `iam:route:{service}` or `iam:route:*` (every service except `iam`).
    Route(ServiceScope),
}

impl ReservedPermission {
    /// Parses a reserved key. The fixed words `sensitive`, `wildcard` and `anonymous` win over a
    /// service of the same name.
    ///
    /// # Errors
    ///
    /// [`InvalidPermissionKey::Kind`] when the text does not start with `iam:`,
    /// [`InvalidPermissionKey::Reserved`] for an unknown key and [`InvalidPermissionKey::Service`]
    /// when the service segment is not a service name.
    pub fn parse(value: &str) -> Result<Self, InvalidPermissionKey> {
        let rest = value
            .strip_prefix("iam:")
            .ok_or(InvalidPermissionKey::Kind)?;
        let (family, argument) = rest.split_once(':').ok_or(InvalidPermissionKey::Reserved)?;
        match (family, argument) {
            ("grant", "sensitive") => Ok(Self::GrantSensitive),
            ("grant", "wildcard") => Ok(Self::GrantWildcard),
            ("audit", "read") => Ok(Self::AuditRead),
            ("revoke", "sessions") => Ok(Self::RevokeSessions),
            ("revoke", "global") => Ok(Self::RevokeGlobal),
            ("policy", "resync") => Ok(Self::PolicyResync),
            ("route", "anonymous") => Ok(Self::RouteAnonymous),
            ("validate", scope) => ServiceScope::parse(scope).map(Self::Validate),
            ("grant", scope) => ServiceScope::parse(scope).map(Self::Grant),
            ("spec", scope) => ServiceScope::parse(scope).map(Self::Spec),
            ("route", scope) => ServiceScope::parse(scope).map(Self::Route),
            _ => Err(InvalidPermissionKey::Reserved),
        }
    }

    /// Whether this key, held at global scope, admits its family's operations on `service`.
    /// `iam:grant:*` and `iam:validate:*` cover every service; `iam:spec:*` and `iam:route:*`
    /// cover every service except `iam`; a key without a service segment covers none.
    #[must_use]
    pub fn covers_service(&self, service: &ServiceName) -> bool {
        match self {
            Self::Validate(ServiceScope::All) | Self::Grant(ServiceScope::All) => true,
            Self::Spec(ServiceScope::All) | Self::Route(ServiceScope::All) => !service.is_iam(),
            Self::Validate(ServiceScope::Service(own))
            | Self::Grant(ServiceScope::Service(own))
            | Self::Spec(ServiceScope::Service(own))
            | Self::Route(ServiceScope::Service(own)) => own == service,
            Self::GrantSensitive
            | Self::GrantWildcard
            | Self::AuditRead
            | Self::RevokeSessions
            | Self::RevokeGlobal
            | Self::PolicyResync
            | Self::RouteAnonymous => false,
        }
    }

    /// Whether holding this key satisfies a requirement for `required`.
    #[must_use]
    pub fn covers(&self, required: &Self) -> bool {
        if self == required {
            return true;
        }
        match (self, required) {
            (Self::Validate(_), Self::Validate(ServiceScope::Service(service)))
            | (Self::Grant(_), Self::Grant(ServiceScope::Service(service)))
            | (Self::Spec(_), Self::Spec(ServiceScope::Service(service)))
            | (Self::Route(_), Self::Route(ServiceScope::Service(service))) => {
                self.covers_service(service)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for ReservedPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validate(scope) => write!(f, "iam:validate:{scope}"),
            Self::Grant(scope) => write!(f, "iam:grant:{scope}"),
            Self::GrantSensitive => f.write_str("iam:grant:sensitive"),
            Self::GrantWildcard => f.write_str("iam:grant:wildcard"),
            Self::Spec(scope) => write!(f, "iam:spec:{scope}"),
            Self::AuditRead => f.write_str("iam:audit:read"),
            Self::RevokeSessions => f.write_str("iam:revoke:sessions"),
            Self::RevokeGlobal => f.write_str("iam:revoke:global"),
            Self::PolicyResync => f.write_str("iam:policy:resync"),
            Self::RouteAnonymous => f.write_str("iam:route:anonymous"),
            Self::Route(scope) => write!(f, "iam:route:{scope}"),
        }
    }
}

#[cfg(test)]
mod tests;
