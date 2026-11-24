//! The alerts of the anti-entropy task: what is wrong, and the runbook that tells the operator what
//! to do.

/// The runbook of an alert in `docs/operations.md`.
pub const TOPIC_AHEAD_RUNBOOK: &str = "topic-ahead";

/// The runbook of the alerts that the resync of Story 7.10 repairs.
pub const RESYNC_RUNBOOK: &str = "resync";

/// Something the task cannot repair: the operator must act.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AntiEntropyAlert {
    /// The topic holds a version above the one PostgreSQL holds.
    #[error("the state topic is at version {topic} but PostgreSQL is at version {store}")]
    TopicAhead {
        /// The newest `__head` version on the topic.
        topic: i64,
        /// The PostgreSQL version.
        store: i64,
    },
    /// The digest of the topic differs from the digest it or PostgreSQL holds.
    #[error("the digest at version {version} is {found} where {expected} is expected")]
    DigestMismatch {
        /// The version that was compared.
        version: i64,
        /// The digest that was expected.
        expected: String,
        /// The digest that was found.
        found: String,
    },
    /// A record of the topic cannot be read.
    #[error("the record at offset {offset} of the state topic is unreadable: {reason}")]
    UnreadableRecord {
        /// The offset of the record.
        offset: i64,
        /// Why it cannot be read.
        reason: String,
    },
    /// A record was lost, and its outbox row no longer exists to send it again.
    #[error("the record of {key} was lost and its outbox row is gone")]
    LossBeyondRetention {
        /// The key of the lost record.
        key: String,
    },
    /// Every row was published, yet the topic does not hold the version PostgreSQL holds.
    #[error("the state topic is behind PostgreSQL version {store} with nothing left to publish")]
    TopicBehind {
        /// The PostgreSQL version.
        store: i64,
    },
}

impl AntiEntropyAlert {
    /// The runbook section of `docs/operations.md` that the alert names.
    #[must_use]
    pub const fn runbook(&self) -> &'static str {
        match self {
            Self::TopicAhead { .. } => TOPIC_AHEAD_RUNBOOK,
            Self::DigestMismatch { .. }
            | Self::UnreadableRecord { .. }
            | Self::LossBeyondRetention { .. }
            | Self::TopicBehind { .. } => RESYNC_RUNBOOK,
        }
    }
}

#[cfg(test)]
mod tests;
