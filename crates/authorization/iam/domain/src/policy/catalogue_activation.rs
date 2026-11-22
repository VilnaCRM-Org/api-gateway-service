//! The result of an activation or a retirement for the catalogue of one service (FR-32, FR-36,
//! FR-38).

use std::collections::BTreeSet;

use crate::policy::compiled_role_set::GrantStatus;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;

/// One grant of a role to an exact catalogue key, with its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// The role that holds the grant.
    pub role: RoleId,
    /// The granted key.
    pub key: PermissionKey,
    /// Whether the grant takes part in decisions.
    pub status: GrantStatus,
}

/// A key whose flags differ between the catalogue before and the catalogue after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagChange {
    /// The key.
    pub key: PermissionKey,
    /// Its flags before.
    pub before: PermissionFlags,
    /// Its flags after.
    pub after: PermissionFlags,
}

impl FlagChange {
    /// Whether the change removes the sensitive or the always-audit flag.
    #[must_use]
    pub const fn is_downgrade(&self) -> bool {
        self.before.is_downgraded_by(self.after)
    }
}

/// A grant that became inactive because its key left the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrphanedGrant {
    /// The role that holds the grant.
    pub role: RoleId,
    /// The key that left the catalogue.
    pub key: PermissionKey,
}

/// A rename of a key and the roles whose grants moved to the new key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRename {
    /// The old key.
    pub from: PermissionKey,
    /// The new key.
    pub to: PermissionKey,
    /// The roles whose grant moved, in id order.
    pub roles: Vec<RoleId>,
}

/// What an activation or a retirement does to the catalogue of one service.
///
/// It lists the keys it creates, the flags it changes, the grants it orphans and the renames it
/// applies, with the grants as they stand afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueActivation {
    /// The keys of the catalogue after that the catalogue before lacked, in key order.
    pub created_keys: Vec<PermissionKey>,
    /// Every key of both catalogues whose flags differ, in key order.
    pub flag_changes: Vec<FlagChange>,
    /// The flag changes that remove a flag, in key order; each is also in `flag_changes`.
    pub flag_downgrades: Vec<FlagChange>,
    /// The grants that became inactive, in role then key order.
    pub orphaned_grants: Vec<OrphanedGrant>,
    /// The renames applied, in old-key order.
    pub renames: Vec<KeyRename>,
    /// Every grant after the rename and the orphaning, in role then key order.
    pub grants: Vec<GrantRecord>,
}

impl CatalogueActivation {
    /// The keys with at least one orphaned grant, in key order.
    #[must_use]
    pub fn orphaned_keys(&self) -> Vec<PermissionKey> {
        self.orphaned_grants
            .iter()
            .map(|orphaned| orphaned.key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The roles that lost a grant, in id order.
    #[must_use]
    pub fn affected_roles(&self) -> Vec<RoleId> {
        self.orphaned_grants
            .iter()
            .map(|orphaned| orphaned.role)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Whether the activation neither orphans a grant nor creates a key, renames one or changes
    /// a flag.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.created_keys.is_empty()
            && self.flag_changes.is_empty()
            && self.orphaned_grants.is_empty()
            && self.renames.is_empty()
    }
}
