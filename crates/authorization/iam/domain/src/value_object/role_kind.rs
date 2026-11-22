//! Whether a role is managed by IAM itself or by administrators.

use crate::error::InvalidRole;

/// The kind of a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleKind {
    /// A role that IAM creates itself, such as `iam-platform-admin`; the API cannot rename,
    /// change or delete it.
    System,
    /// A role created through the API.
    Custom,
}

impl RoleKind {
    /// Parses the text form, `system` or `custom`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRole::Kind`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidRole> {
        match value {
            "system" => Ok(Self::System),
            "custom" => Ok(Self::Custom),
            _ => Err(InvalidRole::Kind),
        }
    }

    /// The text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Custom => "custom",
        }
    }
}

impl std::fmt::Display for RoleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
