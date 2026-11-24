//! Port of the reads and the repair of the anti-entropy task (FR-77): what PostgreSQL holds of the
//! policy and of the outbox, compared with what the state topic holds.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::port::RepositoryError;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;

/// The version and the digest that PostgreSQL holds for the whole policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredHead {
    /// The current policy version.
    pub version: PolicyVersion,
    /// The digest of the whole policy state at that version.
    pub digest: PolicyDigestValue,
}

/// A state row that the relay published, with the offset it was stored at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRecord {
    /// The identity of the outbox row.
    pub id: Uuid,
    /// The record key.
    pub key: String,
    /// The policy version of the row.
    pub version: PolicyVersion,
    /// The offset the broker acknowledged.
    pub offset: i64,
}

/// The newest state row of a key that was written since a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenKey {
    /// The identity of the newest outbox row of the key.
    pub id: Uuid,
    /// The record key.
    pub key: String,
    /// The policy version of that row, the newest PostgreSQL version of the key.
    pub version: PolicyVersion,
    /// The offset the row was published at; `None` while the relay has not published it.
    pub published_offset: Option<i64>,
}

/// Reads the state that the anti-entropy task compares and repairs a lost record.
#[async_trait::async_trait]
pub trait AntiEntropyStore: std::fmt::Debug + Send + Sync {
    /// The policy version and digest of PostgreSQL.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when the policy epoch row is missing and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn head(&self) -> Result<StoredHead, RepositoryError>;

    /// At most `limit` of the newest state rows that were published at or after `since`, newest
    /// offset first.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn recently_published(
        &self,
        since: SystemTime,
        limit: u32,
    ) -> Result<Vec<PublishedRecord>, RepositoryError>;

    /// The newest state row of every key that has a row written at or after `since`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn keys_written_since(
        &self,
        since: SystemTime,
    ) -> Result<Vec<WrittenKey>, RepositoryError>;

    /// The newest state row, whenever it was written, of every key of `keys` that has a row; a key
    /// without a row is left out.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn newest_rows(&self, keys: &[String]) -> Result<Vec<WrittenKey>, RepositoryError>;

    /// The number of state rows the relay has not published yet.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn unpublished_count(&self) -> Result<u64, RepositoryError>;

    /// Clears the publication marks of the row `id`, so the relay sends it again; `false` when the
    /// row no longer exists (the outbox deleted it after its retention) or was not published.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn republish(&self, id: Uuid) -> Result<bool, RepositoryError>;
}
