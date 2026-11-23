//! The catalogue write of one activation or retirement (FR-32, FR-36, FR-38).
//!
//! A change hands it to the unit of work: the version's status, the catalogue entries, the
//! orphaned and renamed grants and the catalogue epoch.

use std::time::SystemTime;

use crate::error::InvalidCatalogueEntry;
use crate::policy::catalogue_activation::{KeyRename, OrphanedGrant};
use crate::value_object::identifier::{PermissionId, SpecId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;

/// The move of a specification version to a new status. The storage applies it only to a version
/// that is still in `from`, so a concurrent change refuses the whole change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecTransition {
    /// The version.
    pub spec_id: SpecId,
    /// The status the version must still hold.
    pub from: SpecStatus,
    /// The status the version takes.
    pub to: SpecStatus,
    /// When the version became active.
    pub activated_at: Option<SystemTime>,
    /// When the version was retired.
    pub retired_at: Option<SystemTime>,
}

/// A catalogue entry to create, active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInsert {
    /// The identifier of the new entry.
    pub id: PermissionId,
    /// The key.
    pub key: PermissionKey,
    /// The flags.
    pub flags: PermissionFlags,
}

/// The new flags of a stored catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFlags {
    /// The key.
    pub key: PermissionKey,
    /// The flags after the change.
    pub flags: PermissionFlags,
}

/// The values of a catalogue statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueStatementParts {
    /// The form of the keys: `Gql` or `Rest`.
    pub kind: PermissionKeyKind,
    /// The service whose catalogue changes.
    pub service: ServiceName,
    /// The status change of the version.
    pub transition: SpecTransition,
    /// The entries to create.
    pub created: Vec<EntryInsert>,
    /// The stored entries whose flags change.
    pub reflagged: Vec<EntryFlags>,
    /// The stored, inactive entries that become active again.
    pub reactivated: Vec<PermissionKey>,
    /// The stored entries that become inactive.
    pub deactivated: Vec<PermissionKey>,
    /// The grants that become inactive; their `orphaned_at` is set to `at`.
    pub orphaned: Vec<OrphanedGrant>,
    /// The grants that move to a new key.
    pub renames: Vec<KeyRename>,
    /// When the change happened.
    pub at: SystemTime,
}

/// One activation or retirement as a statement of the unit of work: it runs in one transaction
/// with the policy version bump and takes the next catalogue epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueStatement(CatalogueStatementParts);

impl CatalogueStatement {
    /// Validates the statement: every key is of the form and the service of the statement.
    ///
    /// # Errors
    ///
    /// [`InvalidCatalogueEntry::KeyKind`] for a form other than `Gql` or `Rest`, or a key of
    /// another form, and [`InvalidCatalogueEntry::OutsideService`] for a key of another service.
    pub fn new(parts: CatalogueStatementParts) -> Result<Self, InvalidCatalogueEntry> {
        if !matches!(parts.kind, PermissionKeyKind::Gql | PermissionKeyKind::Rest) {
            return Err(InvalidCatalogueEntry::KeyKind {
                expected: PermissionKeyKind::Gql.as_str(),
                found: parts.kind,
            });
        }
        let statement = Self(parts);
        statement.keys().try_for_each(|key| statement.admit(key))?;
        Ok(statement)
    }

    /// The values of the statement.
    #[must_use]
    pub const fn parts(&self) -> &CatalogueStatementParts {
        &self.0
    }

    /// Every key the statement names.
    fn keys(&self) -> impl Iterator<Item = &PermissionKey> {
        let parts = &self.0;
        parts
            .created
            .iter()
            .map(|entry| &entry.key)
            .chain(parts.reflagged.iter().map(|entry| &entry.key))
            .chain(&parts.reactivated)
            .chain(&parts.deactivated)
            .chain(parts.orphaned.iter().map(|grant| &grant.key))
            .chain(
                parts
                    .renames
                    .iter()
                    .flat_map(|rename| [&rename.from, &rename.to]),
            )
    }

    fn admit(&self, key: &PermissionKey) -> Result<(), InvalidCatalogueEntry> {
        if key.kind() != self.0.kind {
            return Err(InvalidCatalogueEntry::KeyKind {
                expected: self.0.kind.as_str(),
                found: key.kind(),
            });
        }
        if key.service() != &self.0.service {
            return Err(InvalidCatalogueEntry::OutsideService {
                key: key.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
