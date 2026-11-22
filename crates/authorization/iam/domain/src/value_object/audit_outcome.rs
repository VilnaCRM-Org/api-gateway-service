//! Whether an audited action took effect.

use crate::error::InvalidIamValue;

/// The outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// The change was committed.
    Committed,
    /// The attempt was refused.
    Rejected,
}

impl AuditOutcome {
    /// Parses `committed` or `rejected`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditOutcome`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        match value {
            "committed" => Ok(Self::Committed),
            "rejected" => Ok(Self::Rejected),
            _ => Err(InvalidIamValue::AuditOutcome),
        }
    }

    /// The text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Rejected => "rejected",
        }
    }
}

#[cfg(test)]
mod tests;
