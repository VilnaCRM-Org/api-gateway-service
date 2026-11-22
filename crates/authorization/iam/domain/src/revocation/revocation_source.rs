//! Who caused a revocation.

use crate::error::InvalidIamValue;

/// The origin of a session revocation or a user cut-off, stored as `user-service` or `operator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationSource {
    /// A User service event.
    UserService,
    /// An IAM operator through the management API.
    Operator,
}

impl RevocationSource {
    /// The stored text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserService => "user-service",
            Self::Operator => "operator",
        }
    }

    /// Parses the stored text form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::RevocationSource`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        match value {
            "user-service" => Ok(Self::UserService),
            "operator" => Ok(Self::Operator),
            _ => Err(InvalidIamValue::RevocationSource),
        }
    }
}

#[cfg(test)]
mod tests;
