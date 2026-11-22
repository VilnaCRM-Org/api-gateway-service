//! Why an audited attempt was refused.

use crate::error::InvalidIamValue;

/// A machine-readable reason such as `forbidden` or `escalation.denied`: a lower-case letter
/// followed by lower-case letters, digits, `_` or `.`, at most 100 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditReason(String);

impl AuditReason {
    /// The largest number of characters of a reason.
    pub const MAX_LENGTH: usize = 100;

    /// Validates the code.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditReasonFormat`] when the text breaks a rule.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        let valid = value.len() <= Self::MAX_LENGTH
            && value.starts_with(|first: char| first.is_ascii_lowercase())
            && value.bytes().all(|byte| {
                matches!(byte, b'_' | b'.') || byte.is_ascii_lowercase() || byte.is_ascii_digit()
            });
        if !valid {
            return Err(InvalidIamValue::AuditReasonFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
