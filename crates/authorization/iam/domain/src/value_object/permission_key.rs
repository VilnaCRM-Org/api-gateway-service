//! The permission key: the unit that roles grant and checks require.

use crate::error::InvalidPermissionKey;
use crate::value_object::gql_name::GqlName;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::reserved_permission::ReservedPermission;
use crate::value_object::rest_template::RestTemplate;
use crate::value_object::service_name::ServiceName;

/// The text after the service segment of the GraphQL introspection key.
const INTROSPECTION: &str = "__introspection";

/// The form of a permission key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionKeyKind {
    /// `rest:{service}:{METHOD} {template}`.
    Rest,
    /// `gql:{service}:{Type}.{field}` or `gql:{service}:__introspection`.
    Gql,
    /// A reserved `iam:` key.
    Reserved,
}

impl PermissionKeyKind {
    /// The stable name of the form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Gql => "gql",
            Self::Reserved => "reserved",
        }
    }
}

/// What a GraphQL key names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GqlCoordinate {
    /// A field of a type, such as `Mutation.createRole`.
    Field {
        /// The type.
        type_name: GqlName,
        /// The field.
        field: GqlName,
    },
    /// `__schema` and `__type`, both required through `__introspection`.
    Introspection,
}

impl std::fmt::Display for GqlCoordinate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field { type_name, field } => write!(f, "{type_name}.{field}"),
            Self::Introspection => f.write_str(INTROSPECTION),
        }
    }
}

/// A parsed permission key; every part is validated, so any value of this type prints a valid key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionKey {
    /// `rest:{service}:{METHOD} {template}`.
    Rest {
        /// The service segment.
        service: ServiceName,
        /// The HTTP method.
        method: HttpMethod,
        /// The path template.
        template: RestTemplate,
    },
    /// `gql:{service}:{coordinate}`.
    Gql {
        /// The service segment.
        service: ServiceName,
        /// The coordinate.
        coordinate: GqlCoordinate,
    },
    /// A reserved `iam:` key.
    Reserved(ReservedPermission),
}

impl PermissionKey {
    /// Parses a key in one of its three forms.
    ///
    /// # Errors
    ///
    /// Returns the [`InvalidPermissionKey`] variant that names the first broken part.
    pub fn parse(value: &str) -> Result<Self, InvalidPermissionKey> {
        let (prefix, rest) = value.split_once(':').ok_or(InvalidPermissionKey::Kind)?;
        match prefix {
            "rest" => parse_rest(rest),
            "gql" => parse_gql(rest),
            "iam" => ReservedPermission::parse(value).map(Self::Reserved),
            _ => Err(InvalidPermissionKey::Kind),
        }
    }

    /// The form of the key.
    #[must_use]
    pub const fn kind(&self) -> PermissionKeyKind {
        match self {
            Self::Rest { .. } => PermissionKeyKind::Rest,
            Self::Gql { .. } => PermissionKeyKind::Gql,
            Self::Reserved(_) => PermissionKeyKind::Reserved,
        }
    }

    /// The method and the path template of a REST key; none for a GraphQL or a reserved key.
    #[must_use]
    pub const fn rest_operation(&self) -> Option<(HttpMethod, &RestTemplate)> {
        match self {
            Self::Rest {
                method, template, ..
            } => Some((*method, template)),
            Self::Gql { .. } | Self::Reserved(_) => None,
        }
    }

    /// The service segment; a reserved key belongs to the service `iam`.
    #[must_use]
    pub fn service(&self) -> &ServiceName {
        match self {
            Self::Rest { service, .. } | Self::Gql { service, .. } => service,
            Self::Reserved(_) => ServiceName::iam(),
        }
    }
}

impl std::fmt::Display for PermissionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest {
                service,
                method,
                template,
            } => write!(f, "rest:{service}:{method} {template}"),
            Self::Gql {
                service,
                coordinate,
            } => write!(f, "gql:{service}:{coordinate}"),
            Self::Reserved(reserved) => std::fmt::Display::fmt(reserved, f),
        }
    }
}

/// Splits `{service}:{operation}` and validates the service.
pub(crate) fn split_service(value: &str) -> Result<(ServiceName, &str), InvalidPermissionKey> {
    let (service, operation) = value
        .split_once(':')
        .ok_or(InvalidPermissionKey::Operation)?;
    let service = ServiceName::new(service).map_err(|_error| InvalidPermissionKey::Service)?;
    Ok((service, operation))
}

fn parse_rest(value: &str) -> Result<PermissionKey, InvalidPermissionKey> {
    let (service, operation) = split_service(value)?;
    let (method, template) = operation
        .split_once(' ')
        .ok_or(InvalidPermissionKey::Operation)?;
    let method = HttpMethod::parse(method).ok_or(InvalidPermissionKey::Method)?;
    let template = RestTemplate::parse(template).ok_or(InvalidPermissionKey::Template)?;
    Ok(PermissionKey::Rest {
        service,
        method,
        template,
    })
}

fn parse_gql(value: &str) -> Result<PermissionKey, InvalidPermissionKey> {
    let (service, operation) = split_service(value)?;
    let coordinate = if operation == INTROSPECTION {
        GqlCoordinate::Introspection
    } else {
        let (type_name, field) = operation
            .split_once('.')
            .ok_or(InvalidPermissionKey::Coordinate)?;
        GqlCoordinate::Field {
            type_name: GqlName::parse(type_name).ok_or(InvalidPermissionKey::Coordinate)?,
            field: GqlName::parse(field).ok_or(InvalidPermissionKey::Coordinate)?,
        }
    };
    Ok(PermissionKey::Gql {
        service,
        coordinate,
    })
}

#[cfg(test)]
mod tests;
