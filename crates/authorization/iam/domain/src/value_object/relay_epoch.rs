//! The epoch of the outbox relay.

use crate::error::InvalidIamValue;

/// The epoch of the outbox relay, a counter of 0 or greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayEpoch(i64);

impl RelayEpoch {
    /// The epoch before any relay took over.
    pub const ZERO: Self = Self(0);

    /// Validates the number.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::RelayEpochNegative`] when the value is negative.
    pub const fn new(value: i64) -> Result<Self, InvalidIamValue> {
        if value < 0 {
            return Err(InvalidIamValue::RelayEpochNegative);
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
