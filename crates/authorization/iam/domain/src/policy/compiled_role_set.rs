//! The grants of one role, compiled for lookups by the decision rule.

use std::collections::BTreeSet;

use crate::policy::wildcard_matcher::WildcardMatcher;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::reserved_permission::ReservedPermission;
use crate::value_object::wildcard_pattern::WildcardPattern;

/// Whether a grant still takes part in decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantStatus {
    /// The grant's key is in an active version of its service, or the grant is a pattern.
    Active,
    /// No active version contains the key any more (FR-38): the grant is ignored.
    Orphaned,
}

/// One role's active grants: an exact-key set, the reserved keys and the wildcard patterns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledRoleSet {
    keys: BTreeSet<PermissionKey>,
    reserved: BTreeSet<ReservedPermission>,
    wildcards: BTreeSet<WildcardPattern>,
}

impl CompiledRoleSet {
    /// Compiles the grants of a role; orphaned grants are left out.
    #[must_use]
    pub fn compile<I>(grants: I) -> Self
    where
        I: IntoIterator<Item = (PermissionGrant, GrantStatus)>,
    {
        grants
            .into_iter()
            .filter(|(_, status)| *status == GrantStatus::Active)
            .fold(Self::default(), |set, (grant, _)| set.with(grant))
    }

    /// Compiles a grant set whose grants are all active.
    #[must_use]
    pub fn from_active(grants: &PermissionGrantSet) -> Self {
        grants
            .iter()
            .fold(Self::default(), |set, grant| set.with(grant.clone()))
    }

    /// Whether the role holds `key`, whose catalogue flags are `flags`: exactly, through a
    /// reserved key that covers it (`iam:grant:*` covers `iam:grant:{service}`), or through a
    /// covering wildcard, which never covers a sensitive key.
    #[must_use]
    pub fn holds(&self, key: &PermissionKey, flags: PermissionFlags) -> bool {
        self.keys.contains(key)
            || self.holds_reserved(key)
            || WildcardMatcher::probes(key, flags)
                .iter()
                .any(|pattern| self.wildcards.contains(pattern))
    }

    /// The number of active exact keys, reserved keys included.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// The number of active wildcard patterns.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }

    /// Whether the role holds no active grant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.wildcards.is_empty()
    }

    fn with(mut self, grant: PermissionGrant) -> Self {
        match grant {
            PermissionGrant::Key(key) => {
                if let PermissionKey::Reserved(reserved) = &key {
                    self.reserved.insert(reserved.clone());
                }
                self.keys.insert(key);
            }
            PermissionGrant::Wildcard(pattern) => {
                self.wildcards.insert(pattern);
            }
        }
        self
    }

    fn holds_reserved(&self, key: &PermissionKey) -> bool {
        match key {
            PermissionKey::Reserved(required) => {
                self.reserved.iter().any(|held| held.covers(required))
            }
            PermissionKey::Rest { .. } | PermissionKey::Gql { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests;
