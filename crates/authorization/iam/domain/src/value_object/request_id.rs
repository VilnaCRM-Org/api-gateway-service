//! The caller's request id, echoed in decisions and recorded in the audit log.

use crate::error::InvalidIamValue;
use crate::value_object::text::is_visible_ascii;

/// An opaque request id: 1 to 128 visible ASCII characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    /// The largest number of characters of a request id.
    pub const MAX_LENGTH: usize = 128;

    /// Validates the text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::RequestIdFormat`] when the text is empty, longer than
    /// [`Self::MAX_LENGTH`] or holds a character that is not visible ASCII.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        if !is_visible_ascii(value, Self::MAX_LENGTH) {
            return Err(InvalidIamValue::RequestIdFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
