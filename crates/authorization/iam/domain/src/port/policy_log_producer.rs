//! Port that appends the records of the outbox to the Kafka topics (FR-46, FR-47).

use shared_domain::BoxError;

use crate::port::outbox_store::{OutboxKind, OutboxRow};
use crate::value_object::relay_epoch::RelayEpoch;

/// The version of the record framing that the headers announce (`iam-schema`).
pub const LOG_SCHEMA: &str = "1";

/// The partition of the state topic.
pub const STATE_PARTITION: i32 = 0;

/// One record to append: the topic, the key, the value and the framing headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLogRecord {
    /// The topic of the record.
    pub topic: String,
    /// The key of the record.
    pub key: String,
    /// The partition to write to; `None` lets the producer choose by the key. State records go to
    /// partition 0, the only partition of the state topic.
    pub partition: Option<i32>,
    /// The value; `None` is a tombstone, which still carries its headers.
    pub payload: Option<String>,
    /// The framing headers in the order `iam-version`, `iam-seq`, `iam-count`,
    /// `iam-digest-after`, `iam-op`, `iam-schema`, `iam-log-epoch`, `iam-relay-epoch`; a row that
    /// has no sequence, count or digest (an event) leaves those three out.
    pub headers: Vec<(&'static str, String)>,
}

impl PolicyLogRecord {
    /// The record of `row` published under `relay_epoch`.
    #[must_use]
    pub fn of(row: &OutboxRow, relay_epoch: RelayEpoch) -> Self {
        let mut headers = vec![("iam-version", row.policy_version.value().to_string())];
        if let Some(seq) = row.seq {
            headers.push(("iam-seq", seq.to_string()));
        }
        if let Some(count) = row.count {
            headers.push(("iam-count", count.to_string()));
        }
        if let Some(digest) = row.digest_after {
            headers.push(("iam-digest-after", digest.to_hex()));
        }
        headers.push(("iam-op", operation(row).to_owned()));
        headers.push(("iam-schema", LOG_SCHEMA.to_owned()));
        headers.push(("iam-log-epoch", row.log_epoch.value().to_string()));
        headers.push(("iam-relay-epoch", relay_epoch.value().to_string()));
        Self {
            topic: row.topic.clone(),
            key: row.record_key.clone(),
            partition: (row.kind == OutboxKind::State).then_some(STATE_PARTITION),
            payload: row.payload.clone(),
            headers,
        }
    }
}

/// What the record of `row` does to its key: `event` for an event, `upsert` for a state record
/// with a value and `delete` for a tombstone.
const fn operation(row: &OutboxRow) -> &'static str {
    match (row.kind, row.payload.is_some()) {
        (OutboxKind::Event, _) => "event",
        (OutboxKind::State, true) => "upsert",
        (OutboxKind::State, false) => "delete",
    }
}

/// Records could not be appended.
#[derive(Debug, thiserror::Error)]
pub enum PolicyLogError {
    /// The cluster cannot be reached, refused the records or answered with a failure; nothing of
    /// the call counts as published.
    #[error("the Kafka cluster did not accept the records")]
    Unavailable(#[source] BoxError),
    /// A newer producer instance fenced this one; it must not publish again.
    #[error("the producer was fenced by a newer relay")]
    Fenced(#[source] BoxError),
}

/// Appends records to Kafka and returns their offsets.
///
/// A call that returns `Ok` has the acknowledgement of every record; in transactional mode that
/// means the transaction that holds them committed. A call that fails publishes nothing that a
/// `read_committed` reader can see.
#[async_trait::async_trait]
pub trait PolicyLogProducer: std::fmt::Debug + Send + Sync {
    /// Appends `records` in order and returns the offset of each, in the same order.
    ///
    /// # Errors
    ///
    /// [`PolicyLogError::Unavailable`] when the cluster does not acknowledge them and
    /// [`PolicyLogError::Fenced`] when a newer instance of the producer took over.
    async fn publish(&self, records: &[PolicyLogRecord]) -> Result<Vec<i64>, PolicyLogError>;
}

#[cfg(test)]
mod tests;
