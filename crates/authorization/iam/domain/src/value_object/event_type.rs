//! The type of an event of `iam.events.v1`.

use crate::error::InvalidEventEnvelope;

/// The type of an IAM event, such as `iam.role.created` or `iam.user_role.assigned`.
///
/// It is `iam.<aggregate>.<verb>` and optional further dotted words, every word lower-case letters
/// and digits joined by `_` or `-`, at most 100 characters.
///
/// It matches the envelope pattern `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$` of `iam.events.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventType(String);

impl EventType {
    /// The largest number of characters of a type.
    pub const MAX_LENGTH: usize = 100;

    /// The first word of every type.
    pub const PREFIX: &'static str = "iam.";

    /// Validates the text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEventEnvelope::EventType`] when the text is longer than
    /// [`Self::MAX_LENGTH`], does not start with [`Self::PREFIX`], has fewer than three dotted
    /// words or a word that is not lower-case letters and digits joined by `_` or `-`.
    pub fn new(value: &str) -> Result<Self, InvalidEventEnvelope> {
        let valid = value.len() <= Self::MAX_LENGTH
            && value.starts_with(Self::PREFIX)
            && value.split('.').count() >= 3
            && value
                .split(['.', '_', '-'])
                .all(|word| !word.is_empty() && word.bytes().all(is_word_byte));
        if !valid {
            return Err(InvalidEventEnvelope::EventType);
        }
        Ok(Self(value.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A lower-case ASCII letter or a digit.
const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests;
