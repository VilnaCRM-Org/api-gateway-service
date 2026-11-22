//! The grants of one role.

use std::collections::BTreeSet;

use crate::error::InvalidIamValue;
use crate::value_object::permission_grant::PermissionGrant;

/// The distinct grants of a role, at most 5,000.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionGrantSet(BTreeSet<PermissionGrant>);

impl PermissionGrantSet {
    /// The largest number of distinct grants of a role.
    pub const MAX_GRANTS: usize = 5_000;

    /// Collects the grants, counting a repeated grant once.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::GrantSetTooLarge`] when more than [`Self::MAX_GRANTS`] distinct
    /// grants are given.
    pub fn new<I>(grants: I) -> Result<Self, InvalidIamValue>
    where
        I: IntoIterator<Item = PermissionGrant>,
    {
        let grants: BTreeSet<PermissionGrant> = grants.into_iter().collect();
        if grants.len() > Self::MAX_GRANTS {
            return Err(InvalidIamValue::GrantSetTooLarge);
        }
        Ok(Self(grants))
    }

    /// The number of grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the role grants nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the set holds the grant.
    #[must_use]
    pub fn contains(&self, grant: &PermissionGrant) -> bool {
        self.0.contains(grant)
    }

    /// The grants in order.
    pub fn iter(&self) -> impl Iterator<Item = &PermissionGrant> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests;
