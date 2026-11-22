//! The digest that stands for a credential in memo keys.

/// The SHA-256 digest of a raw credential, computed in infrastructure.
///
/// It is the only form of a credential a memo or cache key holds; `Debug` prints only its first
/// four bytes as eight hexadecimal characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialDigest([u8; Self::LENGTH]);

impl CredentialDigest {
    /// The number of bytes of a SHA-256 digest.
    pub const LENGTH: usize = 32;

    /// Wraps the digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// The first four bytes as eight lower-case hexadecimal characters.
    #[must_use]
    pub fn prefix(&self) -> String {
        self.0
            .iter()
            .take(4)
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect()
    }
}

impl std::fmt::Debug for CredentialDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CredentialDigest({}…)", self.prefix())
    }
}

#[cfg(test)]
mod tests;
