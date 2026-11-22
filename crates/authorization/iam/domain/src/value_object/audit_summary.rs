//! The before or after value of an audited change.

use crate::error::InvalidIamValue;
use crate::value_object::text::holds_token;

/// A summary of the state before or after an audited change: identifiers, role names and
/// permission keys only.
///
/// It holds 1 to 4,096 bytes of printable characters on one line, so a specification body (which
/// spans lines) does not fit, and it never holds a word shaped like a JSON Web Token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditSummary(String);

impl AuditSummary {
    /// The largest number of bytes of a summary.
    pub const MAX_LENGTH: usize = 4096;

    /// Validates the text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditSummaryFormat`] when the text is empty, longer than
    /// [`Self::MAX_LENGTH`] bytes, holds a control character or a word shaped like a token.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        let valid = !value.is_empty()
            && value.len() <= Self::MAX_LENGTH
            && !value.chars().any(char::is_control)
            && !holds_token(value);
        if !valid {
            return Err(InvalidIamValue::AuditSummaryFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
