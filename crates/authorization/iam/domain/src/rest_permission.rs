//! The `RestPermission` entity: one catalogue entry for a REST operation of a service (FR-36, FR-37).

use crate::error::InvalidCatalogueEntry;
use crate::value_object::identifier::PermissionId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};
use crate::value_object::service_name::ServiceName;

/// The stored state of a REST catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPermissionParts {
    /// The identifier.
    pub id: PermissionId,
    /// The key `rest:{service}:{METHOD} {template}`.
    pub key: PermissionKey,
    /// The most restrictive flags across the active versions.
    pub flags: PermissionFlags,
    /// Whether some active version holds the key.
    pub active: bool,
}

/// A catalogue entry of a REST key. Its key never changes; the flags follow the union of the
/// active versions and the entry turns inactive when no active version holds the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPermission {
    parts: RestPermissionParts,
}

impl RestPermission {
    /// A new, active entry.
    ///
    /// # Errors
    ///
    /// [`InvalidCatalogueEntry::KeyKind`] when the key is not a REST key.
    pub fn create(
        id: PermissionId,
        key: PermissionKey,
        flags: PermissionFlags,
    ) -> Result<Self, InvalidCatalogueEntry> {
        Self::restore(RestPermissionParts {
            id,
            key,
            flags,
            active: true,
        })
    }

    /// Rebuilds a stored entry.
    ///
    /// # Errors
    ///
    /// [`InvalidCatalogueEntry::KeyKind`] when the key is not a REST key.
    pub fn restore(parts: RestPermissionParts) -> Result<Self, InvalidCatalogueEntry> {
        match parts.key.kind() {
            PermissionKeyKind::Rest => Ok(Self { parts }),
            found @ (PermissionKeyKind::Gql | PermissionKeyKind::Reserved) => {
                Err(InvalidCatalogueEntry::KeyKind {
                    expected: PermissionKeyKind::Rest.as_str(),
                    found,
                })
            }
        }
    }

    /// The state of the entry.
    #[must_use]
    pub const fn parts(&self) -> &RestPermissionParts {
        &self.parts
    }

    /// The service of the key.
    #[must_use]
    pub fn service(&self) -> &ServiceName {
        self.parts.key.service()
    }

    /// Sets the flags to the union of the active versions.
    pub const fn set_flags(&mut self, flags: PermissionFlags) {
        self.parts.flags = flags;
    }

    /// Marks the entry active: an active version holds the key again.
    pub const fn activate(&mut self) {
        self.parts.active = true;
    }

    /// Marks the entry inactive: no active version holds the key.
    pub const fn deactivate(&mut self) {
        self.parts.active = false;
    }
}

#[cfg(test)]
mod tests;
