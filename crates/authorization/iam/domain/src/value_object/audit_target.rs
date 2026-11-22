//! What an audit record is about.

use crate::error::InvalidIamValue;
use crate::value_object::text::is_visible_ascii;

/// The target of an audited action: a type such as `role` and the id of the targeted record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditTarget {
    target_type: String,
    target_id: String,
}

impl AuditTarget {
    /// The largest number of characters of a target type.
    pub const MAX_TYPE_LENGTH: usize = 50;
    /// The largest number of characters of a target id.
    pub const MAX_ID_LENGTH: usize = 255;

    /// Validates the type and the id.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditTargetType`] when the type is not a lower-case letter
    /// followed by lower-case letters, digits or `_` of at most [`Self::MAX_TYPE_LENGTH`]
    /// characters, and [`InvalidIamValue::AuditTargetId`] when the id is empty, longer than
    /// [`Self::MAX_ID_LENGTH`] or holds a character that is not visible ASCII.
    pub fn new(target_type: &str, target_id: &str) -> Result<Self, InvalidIamValue> {
        if !is_lower_case_word(target_type, Self::MAX_TYPE_LENGTH) {
            return Err(InvalidIamValue::AuditTargetType);
        }
        if !is_visible_ascii(target_id, Self::MAX_ID_LENGTH) {
            return Err(InvalidIamValue::AuditTargetId);
        }
        Ok(Self {
            target_type: target_type.to_owned(),
            target_id: target_id.to_owned(),
        })
    }

    /// The type of the target.
    #[must_use]
    pub fn target_type(&self) -> &str {
        &self.target_type
    }

    /// The id of the target.
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// A lower-case letter followed by lower-case letters, digits or `_`, at most `max` bytes.
fn is_lower_case_word(value: &str, max: usize) -> bool {
    value.len() <= max
        && value.starts_with(|first: char| first.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests;
