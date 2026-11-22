//! The idempotency key of an administrative write.

use crate::error::InvalidIamValue;
use crate::value_object::text::is_visible_ascii;

/// An opaque idempotency key: 1 to 255 visible ASCII characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// The largest number of characters of a key.
    pub const MAX_LENGTH: usize = 255;

    /// Validates the text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::IdempotencyKeyFormat`] when the text is empty, longer than
    /// [`Self::MAX_LENGTH`] or holds a character that is not visible ASCII.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        if !is_visible_ascii(value, Self::MAX_LENGTH) {
            return Err(InvalidIamValue::IdempotencyKeyFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
