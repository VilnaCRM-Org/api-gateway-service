//! How a change affects authorization decisions.

/// Whether a change affects decisions, and whether it takes access away.
///
/// A change that affects decisions takes the next policy version; a revocation-class change also
/// affects decisions and is the kind that the write mode `propagated` fences (Story 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionEffect {
    /// No decision changes, for example loading a draft specification.
    Unaffected,
    /// Decisions change and access may be granted.
    Affected,
    /// Decisions change and access is taken away, for example a revoked assignment.
    RevocationClass,
}

impl DecisionEffect {
    /// Whether the change takes the next policy version.
    #[must_use]
    pub const fn affects_decisions(self) -> bool {
        !matches!(self, Self::Unaffected)
    }

    /// Whether the change takes access away.
    #[must_use]
    pub const fn is_revocation_class(self) -> bool {
        matches!(self, Self::RevocationClass)
    }
}

#[cfg(test)]
mod tests;
