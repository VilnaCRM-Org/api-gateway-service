//! The permission catalogue of one service and one key form: the union of its active versions
//! (FR-32, FR-36, FR-38).

use std::collections::BTreeMap;

use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{GqlCoordinate, PermissionKey, PermissionKeyKind};
use crate::value_object::rest_operation_set::RestOperationSet;
use crate::value_object::service_name::ServiceName;

/// The keys of one service in one form (`gql` or `rest`) with their flags.
///
/// The catalogue is the union of the keys of every active version of the service; a key that
/// several versions hold carries the most restrictive flags of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionCatalogue {
    service: ServiceName,
    kind: PermissionKeyKind,
    entries: BTreeMap<PermissionKey, PermissionFlags>,
}

impl PermissionCatalogue {
    /// A catalogue without keys: the state of a service without an active version.
    #[must_use]
    pub const fn empty(service: ServiceName, kind: PermissionKeyKind) -> Self {
        Self {
            service,
            kind,
            entries: BTreeMap::new(),
        }
    }

    /// The GraphQL catalogue of the active versions of `service`: every `{Type}.{field}` of every
    /// version (root fields are fields of `Query`, `Mutation` and `Subscription`) and, once at
    /// least one version is active, `gql:{service}:__introspection`.
    #[must_use]
    pub fn for_graphql<'versions, I>(service: &ServiceName, versions: I) -> Self
    where
        I: IntoIterator<Item = &'versions CoordinateSet>,
    {
        let mut catalogue = Self::empty(service.clone(), PermissionKeyKind::Gql);
        let mut any_version = false;
        for version in versions {
            any_version = true;
            for (coordinate, flags) in version.iter() {
                catalogue.insert(coordinate.permission_key(service), flags);
            }
        }
        if any_version {
            let introspection = PermissionKey::Gql {
                service: service.clone(),
                coordinate: GqlCoordinate::Introspection,
            };
            catalogue.insert(introspection, PermissionFlags::NONE);
        }
        catalogue
    }

    /// The REST catalogue of the active versions of `service`: `rest:{service}:{METHOD} {template}`
    /// for every operation of every version.
    #[must_use]
    pub fn for_rest<'versions, I>(service: &ServiceName, versions: I) -> Self
    where
        I: IntoIterator<Item = &'versions RestOperationSet>,
    {
        let mut catalogue = Self::empty(service.clone(), PermissionKeyKind::Rest);
        for version in versions {
            for (operation, details) in version.iter() {
                let key = PermissionKey::Rest {
                    service: service.clone(),
                    method: operation.method,
                    template: operation.template.as_rest_template().clone(),
                };
                catalogue.insert(key, details.flags);
            }
        }
        catalogue
    }

    /// The service of the catalogue.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The form of the keys of the catalogue.
    #[must_use]
    pub const fn kind(&self) -> PermissionKeyKind {
        self.kind
    }

    /// Whether `key` is of the service and the form of this catalogue, whether it is in it or not.
    #[must_use]
    pub fn is_in_scope(&self, key: &PermissionKey) -> bool {
        key.kind() == self.kind && key.service() == &self.service
    }

    /// Whether the catalogue holds the key.
    #[must_use]
    pub fn contains(&self, key: &PermissionKey) -> bool {
        self.entries.contains_key(key)
    }

    /// The flags of the key, when the catalogue holds it.
    #[must_use]
    pub fn flags(&self, key: &PermissionKey) -> Option<PermissionFlags> {
        self.entries.get(key).copied()
    }

    /// The number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalogue holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The keys with their flags, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&PermissionKey, PermissionFlags)> {
        self.entries.iter().map(|(key, flags)| (key, *flags))
    }

    fn insert(&mut self, key: PermissionKey, flags: PermissionFlags) {
        self.entries
            .entry(key)
            .and_modify(|stored| *stored = stored.most_restrictive(flags))
            .or_insert(flags);
    }
}

#[cfg(test)]
mod tests;
