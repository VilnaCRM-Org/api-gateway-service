//! The content hash of a specification version.

use crate::value_object::request_digest::RequestDigest;

/// The SHA-256 digest of a specification document: exactly 32 bytes.
///
/// The digest is computed outside the domain (the domain has no crypto); two uploads of one
/// service with the same hash are the same version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash([u8; Self::LENGTH]);

impl ContentHash {
    /// The number of bytes of a hash.
    pub const LENGTH: usize = 32;

    /// Copies the bytes; `None` when `bytes` is not [`Self::LENGTH`] bytes long.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        <[u8; Self::LENGTH]>::try_from(bytes).ok().map(Self)
    }

    /// The bytes of the hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<RequestDigest> for ContentHash {
    /// The SHA-256 digest that the digester port computed over a document is its content hash.
    fn from(digest: RequestDigest) -> Self {
        Self(*digest.as_bytes())
    }
}

impl std::fmt::Display for ContentHash {
    /// The lower-case hexadecimal form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests;
