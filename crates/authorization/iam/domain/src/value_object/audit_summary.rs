//! The before or after value of an audited change.

use crate::error::InvalidIamValue;

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
            && !value.split(is_word_boundary).any(looks_like_token);
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

/// Every character that cannot be part of a base64url token segment or its `.` separator.
const fn is_word_boundary(character: char) -> bool {
    !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
}

/// Three non-empty dot-separated segments whose first one starts like an encoded JSON header.
fn looks_like_token(word: &str) -> bool {
    word.starts_with("eyJ")
        && word.split('.').count() == 3
        && word.split('.').all(|segment| !segment.is_empty())
}

#[cfg(test)]
mod tests;
