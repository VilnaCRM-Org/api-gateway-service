//! The optimistic-concurrency version of an IAM record.

use crate::error::{InvalidIamValue, VersionConflict};

/// The version of one record: 1 when it is created, increased by every change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityVersion(i64);

impl EntityVersion {
    /// The version of a new record.
    pub const INITIAL: Self = Self(1);

    /// Validates the number.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::EntityVersionRange`] when the value is below 1.
    pub const fn new(value: i64) -> Result<Self, InvalidIamValue> {
        if value < 1 {
            return Err(InvalidIamValue::EntityVersionRange);
        }
        Ok(Self(value))
    }

    /// The number.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// The version after one more change.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::EntityVersionRange`] when the version is already the largest.
    pub const fn next(self) -> Result<Self, InvalidIamValue> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(InvalidIamValue::EntityVersionRange),
        }
    }

    /// Checks the version a change expects against this, the current version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionConflict::Missing`] when the change names no version and
    /// [`VersionConflict::Stale`] when it names another one.
    pub fn check(self, expected: Option<Self>) -> Result<(), VersionConflict> {
        let expected = expected.ok_or(VersionConflict::Missing)?;
        if expected != self {
            return Err(VersionConflict::Stale {
                expected,
                current: self,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
