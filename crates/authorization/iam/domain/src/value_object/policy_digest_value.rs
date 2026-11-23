//! The digest of the policy state.

use crate::error::InvalidIamValue;

/// The digest of the whole policy state: exactly 16 bytes, all zeros before the first change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyDigestValue([u8; Self::LENGTH]);

impl PolicyDigestValue {
    /// The number of bytes of a digest.
    pub const LENGTH: usize = 16;

    /// The digest of the empty policy state, and the identity of [`Self::combined`].
    pub const ZERO: Self = Self([0; Self::LENGTH]);

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

    /// The bitwise exclusive or of two digests: how a changed entity moves the digest of the whole
    /// state (`digest ^= h_old ^ h_new`). It is commutative and associative, and a value combined
    /// with itself gives [`Self::ZERO`].
    #[must_use]
    pub fn combined(self, other: Self) -> Self {
        let mut bytes = self.0;
        for (byte, other_byte) in bytes.iter_mut().zip(other.0) {
            *byte ^= other_byte;
        }
        Self(bytes)
    }

    /// A digest of exactly 16 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// The 32 lower-case hexadecimal characters of the digest.
    #[must_use]
    pub fn to_hex(self) -> String {
        self.0
            .iter()
            .flat_map(|byte| [byte / 16, byte % 16])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect()
    }

    /// Reads the form of [`Self::to_hex`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::PolicyDigestLength`] when the text is not exactly 32 lower-case
    /// hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, InvalidIamValue> {
        let lower_case_hexadecimal = |character: char| matches!(character, '0'..='9' | 'a'..='f');
        if text.len() != Self::LENGTH * 2 || !text.chars().all(lower_case_hexadecimal) {
            return Err(InvalidIamValue::PolicyDigestLength);
        }
        let bytes = text
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or(InvalidIamValue::PolicyDigestLength)?;
        Self::new(&bytes)
    }

    /// The bytes of the digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests;
