//! The structured wildcard forms a role may grant.

use crate::error::InvalidPermissionKey;
use crate::value_object::gql_name::GqlName;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::permission_key::split_service;
use crate::value_object::service_name::ServiceName;

/// Parses the text after the service segment of one prefix.
type OperationParser = fn(ServiceName, &str) -> Result<WildcardPattern, InvalidPermissionKey>;

/// Exactly the four wildcard forms of FR-10; no other placement of `*` exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WildcardPattern {
    /// `gql:{service}:{Type}.*`: every field of one type.
    GqlType {
        /// The service segment.
        service: ServiceName,
        /// The type.
        type_name: GqlName,
    },
    /// `gql:{service}:*`: every GraphQL key of the service.
    GqlService {
        /// The service segment.
        service: ServiceName,
    },
    /// `rest:{service}:{METHOD} *`: every REST operation of one method.
    RestMethod {
        /// The service segment.
        service: ServiceName,
        /// The HTTP method.
        method: HttpMethod,
    },
    /// `rest:{service}:*`: every REST key of the service.
    RestService {
        /// The service segment.
        service: ServiceName,
    },
}

impl WildcardPattern {
    /// Parses one of the four forms.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPermissionKey::Service`] when the service segment is not a service name and
    /// [`InvalidPermissionKey::Wildcard`] for every other text.
    pub fn parse(value: &str) -> Result<Self, InvalidPermissionKey> {
        let (prefix, rest) = value
            .split_once(':')
            .ok_or(InvalidPermissionKey::Wildcard)?;
        let parse_operation: OperationParser = match prefix {
            "gql" => parse_gql,
            "rest" => parse_rest,
            _ => return Err(InvalidPermissionKey::Wildcard),
        };
        let (service, operation) = split_service(rest).map_err(only_service_errors)?;
        parse_operation(service, operation)
    }

    /// The service segment.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        match self {
            Self::GqlType { service, .. }
            | Self::GqlService { service }
            | Self::RestMethod { service, .. }
            | Self::RestService { service } => service,
        }
    }
}

impl std::fmt::Display for WildcardPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GqlType { service, type_name } => write!(f, "gql:{service}:{type_name}.*"),
            Self::GqlService { service } => write!(f, "gql:{service}:*"),
            Self::RestMethod { service, method } => write!(f, "rest:{service}:{method} *"),
            Self::RestService { service } => write!(f, "rest:{service}:*"),
        }
    }
}

/// Keeps a service error and reports every other failure as a wrong wildcard form.
fn only_service_errors(error: InvalidPermissionKey) -> InvalidPermissionKey {
    if error == InvalidPermissionKey::Service {
        error
    } else {
        InvalidPermissionKey::Wildcard
    }
}

fn parse_gql(
    service: ServiceName,
    operation: &str,
) -> Result<WildcardPattern, InvalidPermissionKey> {
    if operation == "*" {
        return Ok(WildcardPattern::GqlService { service });
    }
    operation
        .strip_suffix(".*")
        .and_then(GqlName::parse)
        .map(|type_name| WildcardPattern::GqlType { service, type_name })
        .ok_or(InvalidPermissionKey::Wildcard)
}

fn parse_rest(
    service: ServiceName,
    operation: &str,
) -> Result<WildcardPattern, InvalidPermissionKey> {
    if operation == "*" {
        return Ok(WildcardPattern::RestService { service });
    }
    operation
        .strip_suffix(" *")
        .and_then(HttpMethod::parse)
        .map(|method| WildcardPattern::RestMethod { service, method })
        .ok_or(InvalidPermissionKey::Wildcard)
}

#[cfg(test)]
mod tests;
