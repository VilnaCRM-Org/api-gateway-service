//! The digest of the request body of an idempotent write.

use crate::error::InvalidIamValue;

/// The SHA-256 digest of the canonical request of an idempotent write: exactly 32 bytes, computed
/// outside the domain. A replay with the same key and another digest is a different request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestDigest([u8; Self::LENGTH]);

impl RequestDigest {
    /// The number of bytes of a digest.
    pub const LENGTH: usize = 32;

    /// Validates the length and copies the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::RequestDigestLength`] when `bytes` is not [`Self::LENGTH`] bytes
    /// long.
    pub fn new(bytes: &[u8]) -> Result<Self, InvalidIamValue> {
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map(Self)
            .map_err(|_error| InvalidIamValue::RequestDigestLength)
    }

    /// The bytes of the digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests;
