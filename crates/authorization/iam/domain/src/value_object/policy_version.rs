//! The version of the whole policy.

use crate::error::InvalidIamValue;

/// The gap-free, commit-ordered version of the policy: 0 or greater, 0 before the first change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(i64);

impl PolicyVersion {
    /// Validates the number.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::PolicyVersionNegative`] when the value is negative.
    pub const fn new(value: i64) -> Result<Self, InvalidIamValue> {
        if value < 0 {
            return Err(InvalidIamValue::PolicyVersionNegative);
        }
        Ok(Self(value))
    }

    /// The number.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests;
