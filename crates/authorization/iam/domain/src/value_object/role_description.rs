//! The description of a role.

use crate::error::InvalidRole;

/// A role description of at most 1,000 Unicode scalar values, stored as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDescription(String);

impl RoleDescription {
    /// The largest number of Unicode scalar values.
    pub const MAX_CHARS: usize = 1_000;

    /// Validates the description; the length is counted with `chars().count()`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRole::DescriptionLength`] when the value is longer than
    /// [`Self::MAX_CHARS`].
    pub fn new(value: String) -> Result<Self, InvalidRole> {
        if value.chars().count() > Self::MAX_CHARS {
            return Err(InvalidRole::DescriptionLength);
        }
        Ok(Self(value))
    }

    /// The description as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
