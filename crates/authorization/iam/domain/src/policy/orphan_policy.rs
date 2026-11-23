//! `OrphanPolicy`: which grants become inactive when the active versions of a service change, and
//! the rule that an orphaned grant never reactivates (FR-32, FR-36, FR-38).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::RenameRefused;
use crate::policy::catalogue_activation::{
    CatalogueActivation, FlagChange, GrantRecord, KeyRename, OrphanedGrant,
};
use crate::policy::compiled_role_set::GrantStatus;
use crate::policy::permission_catalogue::PermissionCatalogue;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};

/// A map from old keys to new keys of one service and form: the coordinates a new version
/// renames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenameMap(BTreeMap<PermissionKey, PermissionKey>);

impl RenameMap {
    /// A map without renames.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Builds the map from `(old, new)` pairs.
    ///
    /// # Errors
    ///
    /// [`RenameRefused::Unchanged`] for a key renamed to itself, [`RenameRefused::Scope`] when the
    /// two keys differ in service or form or are reserved keys, [`RenameRefused::Duplicate`] for an
    /// old key renamed twice and [`RenameRefused::Chained`] for a key that is both an old and a
    /// new key.
    pub fn new<I>(pairs: I) -> Result<Self, RenameRefused>
    where
        I: IntoIterator<Item = (PermissionKey, PermissionKey)>,
    {
        Self::from_pairs(pairs.into_iter().collect())
    }

    /// [`RenameMap::new`] over collected pairs, so that one copy of the checks serves every
    /// iterator type.
    fn from_pairs(pairs: Vec<(PermissionKey, PermissionKey)>) -> Result<Self, RenameRefused> {
        let mut map = BTreeMap::new();
        for (from, to) in pairs {
            if from == to {
                return Err(RenameRefused::Unchanged {
                    key: from.to_string(),
                });
            }
            if from.kind() != to.kind()
                || from.kind() == PermissionKeyKind::Reserved
                || from.service() != to.service()
            {
                return Err(RenameRefused::Scope {
                    from: from.to_string(),
                    to: to.to_string(),
                });
            }
            if map.contains_key(&from) {
                return Err(RenameRefused::Duplicate {
                    key: from.to_string(),
                });
            }
            map.insert(from, to);
        }
        if let Some(chained) = map.values().find(|to| map.contains_key(*to)) {
            return Err(RenameRefused::Chained {
                key: chained.to_string(),
            });
        }
        Ok(Self(map))
    }

    /// The new key of an old key.
    #[must_use]
    pub fn target(&self, from: &PermissionKey) -> Option<&PermissionKey> {
        self.0.get(from)
    }

    /// The number of renames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map holds no rename.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `(old, new)` pairs in old-key order.
    pub fn iter(&self) -> impl Iterator<Item = (&PermissionKey, &PermissionKey)> {
        self.0.iter()
    }

    /// Checks that every rename fits the catalogue that takes effect.
    fn check_against(&self, next: &PermissionCatalogue) -> Result<(), RenameRefused> {
        for (from, to) in self.iter() {
            if let Some(outside) = [from, to].into_iter().find(|key| !next.is_in_scope(key)) {
                return Err(RenameRefused::OutsideCatalogue {
                    key: outside.to_string(),
                });
            }
            if !next.contains(to) {
                return Err(RenameRefused::TargetMissing { to: to.to_string() });
            }
            if next.contains(from) {
                return Err(RenameRefused::SourceStillPresent {
                    from: from.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// The grants of a role by `(role, key)`.
type Resolved = BTreeMap<(RoleId, PermissionKey), GrantStatus>;

/// The orphan rules.
///
/// A grant of an exact key of the catalogue's service and form is active while the key is in the
/// catalogue of the active versions and becomes orphaned when it leaves it. An orphaned grant stays
/// inactive when its key comes back: only a new grant makes the key usable again. A rename moves
/// the grants of the old key to the new key before anything is orphaned. Grants of other services,
/// of the other form and reserved keys are not the catalogue's to orphan.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrphanPolicy;

impl OrphanPolicy {
    /// Applies the change from the `previous` catalogue to the `next` one, with `renames`, to
    /// `grants`.
    ///
    /// # Errors
    ///
    /// A [`RenameRefused`] when a rename names a key outside the catalogue, a new key that `next`
    /// lacks or an old key that `next` still holds; nothing is applied then.
    pub fn apply(
        previous: &PermissionCatalogue,
        next: &PermissionCatalogue,
        renames: &RenameMap,
        grants: &[GrantRecord],
    ) -> Result<CatalogueActivation, RenameRefused> {
        renames.check_against(next)?;
        Ok(Self::apply_checked(previous, next, renames, grants))
    }

    /// Applies the change from the `previous` catalogue to the `next` one without renames, as a
    /// retirement does; with no rename there is nothing to refuse.
    #[must_use]
    pub fn apply_without_renames(
        previous: &PermissionCatalogue,
        next: &PermissionCatalogue,
        grants: &[GrantRecord],
    ) -> CatalogueActivation {
        Self::apply_checked(previous, next, &RenameMap::empty(), grants)
    }

    /// Applies the change with renames that were checked against `next`.
    fn apply_checked(
        previous: &PermissionCatalogue,
        next: &PermissionCatalogue,
        renames: &RenameMap,
        grants: &[GrantRecord],
    ) -> CatalogueActivation {
        let (mut resolved, moved_roles) = rename_grants(renames, grants);
        let orphaned_grants = orphan_grants(next, &mut resolved);
        let flag_changes = flag_changes(previous, next);
        CatalogueActivation {
            created_keys: next
                .iter()
                .filter(|(key, _flags)| !previous.contains(key))
                .map(|(key, _flags)| key.clone())
                .collect(),
            flag_downgrades: flag_changes
                .iter()
                .filter(|change| change.is_downgrade())
                .cloned()
                .collect(),
            flag_changes,
            orphaned_grants,
            renames: renames
                .iter()
                .map(|(from, to)| KeyRename {
                    from: from.clone(),
                    to: to.clone(),
                    roles: moved_roles.get(from).cloned().unwrap_or_default(),
                })
                .collect(),
            grants: resolved
                .into_iter()
                .map(|((role, key), status)| GrantRecord { role, key, status })
                .collect(),
        }
    }
}

/// Moves the grants of renamed keys to the new keys; returns the grants by `(role, key)` and, for
/// each old key, the roles whose grant moved.
///
/// A role that already holds the new key keeps that grant as it is. When several grants of a role
/// move to one new key, the result is active if any of them is.
fn rename_grants(
    renames: &RenameMap,
    grants: &[GrantRecord],
) -> (Resolved, BTreeMap<PermissionKey, Vec<RoleId>>) {
    let mut resolved = Resolved::new();
    let mut moving = Vec::new();
    for grant in grants {
        match renames.target(&grant.key) {
            Some(to) => moving.push((grant, to)),
            None => {
                resolved.insert((grant.role, grant.key.clone()), grant.status);
            }
        }
    }
    let settled: BTreeSet<(RoleId, PermissionKey)> = resolved.keys().cloned().collect();
    let mut moved_roles: BTreeMap<PermissionKey, BTreeSet<RoleId>> = BTreeMap::new();
    for (grant, to) in moving {
        moved_roles
            .entry(grant.key.clone())
            .or_default()
            .insert(grant.role);
        let slot = (grant.role, to.clone());
        if settled.contains(&slot) {
            continue;
        }
        resolved
            .entry(slot)
            .and_modify(|status| {
                if grant.status == GrantStatus::Active {
                    *status = GrantStatus::Active;
                }
            })
            .or_insert(grant.status);
    }
    let moved_roles = moved_roles
        .into_iter()
        .map(|(key, roles)| (key, roles.into_iter().collect()))
        .collect();
    (resolved, moved_roles)
}

/// Orphans every active grant of a key in the scope of `next` that `next` lacks; returns them.
fn orphan_grants(next: &PermissionCatalogue, resolved: &mut Resolved) -> Vec<OrphanedGrant> {
    let mut orphaned = Vec::new();
    for ((role, key), status) in resolved {
        if *status == GrantStatus::Active && next.is_in_scope(key) && !next.contains(key) {
            *status = GrantStatus::Orphaned;
            orphaned.push(OrphanedGrant {
                role: *role,
                key: key.clone(),
            });
        }
    }
    orphaned
}

/// The keys of both catalogues whose flags differ.
fn flag_changes(previous: &PermissionCatalogue, next: &PermissionCatalogue) -> Vec<FlagChange> {
    next.iter()
        .filter_map(|(key, after)| {
            let before = previous.flags(key)?;
            (before != after).then(|| FlagChange {
                key: key.clone(),
                before,
                after,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
