//! The write of one rate policy that a change hands to the unit of work.

use crate::rate_policy::{RatePolicy, RatePolicyParts};
use crate::value_object::entity_version::EntityVersion;

/// The write of one rate policy: an insert, or an update guarded by the version the change read. A
/// deletion is an update of a rate policy that carries its deletion time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyStatement {
    rate_policy: RatePolicyParts,
    expected: Option<EntityVersion>,
}

impl RatePolicyStatement {
    /// The insert of a new rate policy; a stored rate policy with the same identifier, or one that
    /// is not deleted with the same name, refuses it as a duplicate.
    #[must_use]
    pub fn insert(rate_policy: &RatePolicy) -> Self {
        Self {
            rate_policy: rate_policy.parts().clone(),
            expected: None,
        }
    }

    /// The update of a stored rate policy that is not deleted and still holds the version
    /// `expected`; any other stored state refuses it as a conflict.
    #[must_use]
    pub fn update(rate_policy: &RatePolicy, expected: EntityVersion) -> Self {
        Self {
            rate_policy: rate_policy.parts().clone(),
            expected: Some(expected),
        }
    }

    /// The state of the rate policy to store.
    #[must_use]
    pub const fn rate_policy(&self) -> &RatePolicyParts {
        &self.rate_policy
    }

    /// The version the stored rate policy must hold; `None` for an insert.
    #[must_use]
    pub const fn expected(&self) -> Option<EntityVersion> {
        self.expected
    }
}

#[cfg(test)]
mod tests;
