//! How long an administrative write waits before it returns (FR-75).

/// What a write waits for before it returns.
///
/// `Published` returns once the relay's Kafka acknowledgement of the policy version is stored;
/// `Propagated` additionally waits for the gateway pods and is delivered by Story 13.4, so a
/// request for it is refused until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WriteMode {
    /// Wait for the Kafka acknowledgement of the version (the default).
    #[default]
    Published,
    /// Wait for the gateway pods to apply the version.
    Propagated,
}

impl WriteMode {
    /// The lower-case name of the mode, as the `Prefer` header writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Propagated => "propagated",
        }
    }

    /// The mode that a lower-case name stands for, none for any other text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "published" => Some(Self::Published),
            "propagated" => Some(Self::Propagated),
            _ => None,
        }
    }

    /// Whether the service delivers the mode yet.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Published)
    }
}

#[cfg(test)]
mod tests;
