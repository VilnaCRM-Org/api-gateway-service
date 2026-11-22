//! The digest of the policy state.

use crate::error::InvalidIamValue;

/// The digest of the whole policy state: exactly 16 bytes, all zeros before the first change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyDigestValue([u8; Self::LENGTH]);

impl PolicyDigestValue {
    /// The number of bytes of a digest.
    pub const LENGTH: usize = 16;

    /// Validates the length and copies the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::PolicyDigestLength`] when `bytes` is not [`Self::LENGTH`] bytes long.
    pub fn new(bytes: &[u8]) -> Result<Self, InvalidIamValue> {
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map(Self)
            .map_err(|_error| InvalidIamValue::PolicyDigestLength)
    }

    /// The bytes of the digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests;
