//! Port of the outbox that the relay drains: the unpublished rows, the takeover of the relay and
//! the marks that a row reached Kafka (FR-46, FR-47).

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::port::RepositoryError;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// The two shapes of an outbox row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxKind {
    /// A record of the policy state topic: framed by sequence, count and digest.
    State,
    /// A domain event of the events topic.
    Event,
}

/// One row of the outbox as the relay reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The identity of the row.
    pub id: Uuid,
    /// Whether the row is a state record or an event.
    pub kind: OutboxKind,
    /// The topic the row goes to.
    pub topic: String,
    /// The record key.
    pub record_key: String,
    /// The record value; `None` is a tombstone.
    pub payload: Option<String>,
    /// The policy version of the transaction that wrote the row.
    pub policy_version: PolicyVersion,
    /// The position in the version, from 1; state rows only.
    pub seq: Option<u32>,
    /// The number of rows of the version; state rows only.
    pub count: Option<u32>,
    /// The digest of the policy state once the row is applied; state rows only.
    pub digest_after: Option<PolicyDigestValue>,
    /// The log epoch of the row.
    pub log_epoch: LogEpoch,
    /// The type of the event; event rows only.
    pub event_type: Option<String>,
}

/// A row that Kafka acknowledged, with the offset it was stored at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedRow {
    /// The identity of the row.
    pub id: Uuid,
    /// The offset of the record in its partition.
    pub offset: i64,
}

/// What a relay that takes over learns: its epoch and the records to send again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTakeover {
    /// The epoch of the new leader, one above the epoch of the previous one.
    pub epoch: RelayEpoch,
    /// The latest state row of every key that the previous leaders published, to publish again
    /// under the new epoch before anything else.
    pub republish: Vec<OutboxRow>,
}

/// Reads and marks the rows of the outbox.
///
/// Only the replica that holds the advisory lock of the relay calls it; the marks are still
/// fenced by the relay epoch, so a leader that was replaced marks nothing.
#[async_trait::async_trait]
pub trait OutboxStore: std::fmt::Debug + Send + Sync {
    /// At most `limit` unpublished rows in `(policy_version, seq)` order.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn claim_unpublished(&self, limit: u32) -> Result<Vec<OutboxRow>, RepositoryError>;

    /// The relay epoch that the policy epoch holds now.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn current_relay_epoch(&self) -> Result<RelayEpoch, RepositoryError>;

    /// Increments the relay epoch, in one transaction, and returns the new epoch with the latest
    /// published state row of every key.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails; the epoch is not changed then.
    async fn take_over_relay(&self) -> Result<RelayTakeover, RepositoryError>;

    /// Stores the offsets and `published_at` of `published` under `epoch`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Conflict`] when the relay epoch is no longer `epoch`, which means
    /// another relay took over and nothing is marked, and [`RepositoryError::Unavailable`] when
    /// the storage fails.
    async fn mark_published(
        &self,
        published: &[PublishedRow],
        epoch: RelayEpoch,
        at: SystemTime,
    ) -> Result<(), RepositoryError>;

    /// Deletes the published rows that were published before `before` and counts them.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn delete_published_before(&self, before: SystemTime) -> Result<u64, RepositoryError>;
}

#[cfg(test)]
mod tests;
