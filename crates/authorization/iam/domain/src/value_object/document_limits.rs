//! The limits a GraphQL document must keep before it is resolved (FR-8, NFR-21).

/// The largest document, nesting, coordinate, alias and fragment counts that are analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentLimits {
    /// The largest document in bytes.
    pub bytes: usize,
    /// The deepest nesting of selection sets, fragments expanded.
    pub depth: usize,
    /// The most field selections of the whole document.
    pub coordinates: usize,
    /// The most aliased fields of the whole document.
    pub aliases: usize,
    /// The most fragment definitions of the whole document.
    pub fragments: usize,
}

impl DocumentLimits {
    /// The byte limit of the decision API: 64 KiB.
    pub const DECISION_API_BYTES: usize = 64 * 1024;

    /// The limits of the decision API: 64 KiB, depth 15, 500 coordinates, 50 aliases and 100
    /// fragments.
    #[must_use]
    pub const fn decision_api() -> Self {
        Self {
            bytes: Self::DECISION_API_BYTES,
            depth: 15,
            coordinates: 500,
            aliases: 50,
            fragments: 100,
        }
    }

    /// The same limits with another byte limit, for a route that sets its own body limit.
    #[must_use]
    pub const fn with_bytes(self, bytes: usize) -> Self {
        Self { bytes, ..self }
    }
}

impl Default for DocumentLimits {
    fn default() -> Self {
        Self::decision_api()
    }
}

#[cfg(test)]
mod tests;
