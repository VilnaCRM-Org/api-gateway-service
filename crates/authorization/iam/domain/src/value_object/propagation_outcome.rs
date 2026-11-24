//! What a write learned about the publication of its policy version (FR-75).

/// The stored status of a version that Kafka acknowledged.
pub const STATUS_PUBLISHED: &str = "published";

/// The stored status of a committed write whose version was not acknowledged in time.
pub const STATUS_COMMITTED_PENDING: &str = "committed_pending_propagation";

/// The outcome of waiting for the publication of the policy version of a write.
///
/// A write that does not affect decisions waits for nothing and has no outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationOutcome {
    /// The relay stored the Kafka acknowledgement of the version's `__head` row at `offset`.
    Published {
        /// The offset of the `__head` record in its partition.
        offset: i64,
    },
    /// The change is committed, and its version was not acknowledged within the wait.
    CommittedPending,
}

impl PropagationOutcome {
    /// The status text that the receipt stores.
    #[must_use]
    pub const fn status(self) -> &'static str {
        match self {
            Self::Published { .. } => STATUS_PUBLISHED,
            Self::CommittedPending => STATUS_COMMITTED_PENDING,
        }
    }

    /// The offset of the version's `__head` record, when the version was published.
    #[must_use]
    pub const fn offset(self) -> Option<i64> {
        match self {
            Self::Published { offset } => Some(offset),
            Self::CommittedPending => None,
        }
    }

    /// Rebuilds an outcome from its stored status and offset; none for an unknown status or a
    /// published status without an offset.
    #[must_use]
    pub fn restore(status: &str, offset: Option<i64>) -> Option<Self> {
        match (status, offset) {
            (STATUS_PUBLISHED, Some(offset)) => Some(Self::Published { offset }),
            (STATUS_COMMITTED_PENDING, _) => Some(Self::CommittedPending),
            _ => None,
        }
    }

    /// Whether the version reached Kafka.
    #[must_use]
    pub const fn is_published(self) -> bool {
        matches!(self, Self::Published { .. })
    }
}

#[cfg(test)]
mod tests;
