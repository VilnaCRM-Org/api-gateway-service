//! The name of a role.

use crate::error::InvalidRole;

/// A role name of 1 to 100 Unicode scalar values without a control character, stored as given.
///
/// Names are unique without regard to case among the roles that are not deleted;
/// [`RoleName::comparison_form`] is the form that uniqueness compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleName(String);

impl RoleName {
    /// The largest number of Unicode scalar values.
    pub const MAX_CHARS: usize = 100;

    /// Validates the name; the length is counted with `chars().count()` and checked first.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRole::NameLength`] when the value is empty or longer than
    /// [`Self::MAX_CHARS`], and [`InvalidRole::NameControlCharacter`] when it holds a control
    /// character.
    pub fn new(value: String) -> Result<Self, InvalidRole> {
        if !(1..=Self::MAX_CHARS).contains(&value.chars().count()) {
            return Err(InvalidRole::NameLength);
        }
        if value.chars().any(char::is_control) {
            return Err(InvalidRole::NameControlCharacter);
        }
        Ok(Self(value))
    }

    /// The name as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The lower-case form that the case-insensitive comparison of names uses.
    #[must_use]
    pub fn comparison_form(&self) -> String {
        self.0.to_lowercase()
    }

    /// Whether the two names are equal without regard to case.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.comparison_form() == other.comparison_form()
    }
}

impl std::fmt::Display for RoleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
