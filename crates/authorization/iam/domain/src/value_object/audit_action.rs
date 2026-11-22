//! What an audit record says was done.

use crate::error::InvalidIamValue;

/// An audited action such as `role.create`: two or more dot-separated words, each a lower-case
/// letter followed by lower-case letters, digits or `_`, at most 100 characters in all.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditAction(String);

impl AuditAction {
    /// The largest number of characters of an action.
    pub const MAX_LENGTH: usize = 100;

    /// Validates the action.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditActionFormat`] when the text breaks a rule.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        let valid =
            value.len() <= Self::MAX_LENGTH && value.contains('.') && value.split('.').all(is_word);
        if !valid {
            return Err(InvalidIamValue::AuditActionFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The action.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A lower-case letter followed by lower-case letters, digits or `_`.
fn is_word(word: &str) -> bool {
    word.starts_with(|first: char| first.is_ascii_lowercase())
        && word
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests;
