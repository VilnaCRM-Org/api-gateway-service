//! A field coordinate of a GraphQL schema.

use crate::value_object::gql_name::GqlName;
use crate::value_object::permission_key::{GqlCoordinate, PermissionKey};
use crate::value_object::service_name::ServiceName;

/// A `{Type}.{field}` coordinate of a schema; root fields are `Query.x`, `Mutation.y` and
/// `Subscription.z`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GraphQlCoordinate {
    type_name: GqlName,
    field: GqlName,
}

impl GraphQlCoordinate {
    /// The coordinate of `field` on `type_name`.
    #[must_use]
    pub const fn new(type_name: GqlName, field: GqlName) -> Self {
        Self { type_name, field }
    }

    /// Parses `{Type}.{field}`; `None` when either name is invalid or the dot is missing.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (type_name, field) = value.split_once('.')?;
        Some(Self::new(
            GqlName::parse(type_name)?,
            GqlName::parse(field)?,
        ))
    }

    /// The type that declares the field.
    #[must_use]
    pub const fn type_name(&self) -> &GqlName {
        &self.type_name
    }

    /// The field.
    #[must_use]
    pub const fn field(&self) -> &GqlName {
        &self.field
    }

    /// The permission key `gql:{service}:{Type}.{field}` of the coordinate.
    #[must_use]
    pub fn permission_key(&self, service: &ServiceName) -> PermissionKey {
        PermissionKey::Gql {
            service: service.clone(),
            coordinate: GqlCoordinate::Field {
                type_name: self.type_name.clone(),
                field: self.field.clone(),
            },
        }
    }

    /// The coordinate that a permission key of `service` names; `None` for a key of another
    /// service, the introspection key and every non-GraphQL key.
    #[must_use]
    pub fn from_permission_key(key: &PermissionKey, service: &ServiceName) -> Option<Self> {
        match key {
            PermissionKey::Gql {
                service: key_service,
                coordinate: GqlCoordinate::Field { type_name, field },
            } if key_service == service => Some(Self::new(type_name.clone(), field.clone())),
            PermissionKey::Gql { .. } | PermissionKey::Rest { .. } | PermissionKey::Reserved(_) => {
                None
            }
        }
    }
}

impl std::fmt::Display for GraphQlCoordinate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.type_name, self.field)
    }
}

#[cfg(test)]
mod tests;
