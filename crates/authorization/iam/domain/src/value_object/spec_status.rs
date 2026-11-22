//! The life-cycle status of a specification version.

/// Where a specification version stands: loaded as `draft`, `active` once its catalogue entries
/// exist, `retired` once it no longer contributes to the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpecStatus {
    /// Loaded, not yet contributing to the catalogue.
    Draft,
    /// Part of the catalogue of its service.
    Active,
    /// No longer part of the catalogue; final.
    Retired,
}

impl SpecStatus {
    /// Every status, in life-cycle order.
    pub const ALL: [Self; 3] = [Self::Draft, Self::Active, Self::Retired];

    /// Parses the stored and wire form; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }

    /// The stored and wire form: `draft`, `active` or `retired`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

impl std::fmt::Display for SpecStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
