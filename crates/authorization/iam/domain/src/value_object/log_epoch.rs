//! The epoch of the policy log.

use crate::error::InvalidIamValue;

/// The epoch of the policy log, a counter of 0 or greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogEpoch(i64);

impl LogEpoch {
    /// The first epoch of the policy log.
    pub const ZERO: Self = Self(0);

    /// Validates the number.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::LogEpochNegative`] when the value is negative.
    pub const fn new(value: i64) -> Result<Self, InvalidIamValue> {
        if value < 0 {
            return Err(InvalidIamValue::LogEpochNegative);
        }
        Ok(Self(value))
    }

    /// The number.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// The epoch that follows this one, or `None` when the counter cannot grow.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests;
