//! A link of the security audit hash chain.

use crate::error::InvalidIamValue;

/// A SHA-256 digest of the audit chain: exactly 32 bytes, all zeros before the first record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditHash([u8; Self::LENGTH]);

impl AuditHash {
    /// The number of bytes of a hash.
    pub const LENGTH: usize = 32;

    /// The hash the chain starts from: 32 zero bytes.
    pub const GENESIS: Self = Self([0; Self::LENGTH]);

    /// Validates the length and copies the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditHashLength`] when `bytes` is not [`Self::LENGTH`] bytes long.
    pub fn new(bytes: &[u8]) -> Result<Self, InvalidIamValue> {
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map(Self)
            .map_err(|_error| InvalidIamValue::AuditHashLength)
    }

    /// The bytes of the hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl std::fmt::Display for AuditHash {
    /// The lower-case hexadecimal form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests;
