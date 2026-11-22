//! The epoch of the policy log.

use crate::error::InvalidIamValue;

/// The epoch of the policy log, a counter of 0 or greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogEpoch(i64);

impl LogEpoch {
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
}

#[cfg(test)]
mod tests;
