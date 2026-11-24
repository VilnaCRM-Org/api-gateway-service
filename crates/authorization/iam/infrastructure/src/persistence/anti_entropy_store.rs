//! PostgreSQL implementation of the anti-entropy store port: the policy head, the recently
//! published state rows, the keys written since a point in time and the repair of a lost record.
//!
//! The statements are checked at run time, so the offline metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    AntiEntropyStore, InvalidIamValue, PolicyDigestValue, PolicyVersion, PublishedRecord,
    RepositoryError, StoredHead, WrittenKey,
};
use shared_domain::Uuid;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid as SqlUuid;

use crate::persistence::revocation::timestamp;

/// Reads `iam_policy_epoch` and `iam_outbox` for the anti-entropy task and clears the publication
/// marks of a row.
#[derive(Debug)]
pub struct PgAntiEntropyStore {
    pool: sqlx::PgPool,
}

const SELECT_HEAD: &str = "SELECT version, digest FROM iam_policy_epoch WHERE id = 1";

/// The state rows published at or after a time, the newest offset first.
const RECENTLY_PUBLISHED: &str = "SELECT id, record_key, policy_version, published_offset
    FROM iam_outbox
    WHERE kind = 'state' AND published_at >= $1
    ORDER BY published_offset DESC
    LIMIT $2";

/// The newest state row of every key that has a row written at or after a time.
const WRITTEN_SINCE: &str = "SELECT DISTINCT ON (record_key) id, record_key, policy_version,
        published_offset
    FROM iam_outbox
    WHERE kind = 'state' AND record_key IN (
        SELECT record_key FROM iam_outbox WHERE kind = 'state' AND occurred_at >= $1
    )
    ORDER BY record_key, policy_version DESC, seq DESC";

/// The newest state row of each of the given keys, whenever it was written.
const NEWEST_OF_KEYS: &str = "SELECT DISTINCT ON (record_key) id, record_key, policy_version,
        published_offset
    FROM iam_outbox
    WHERE kind = 'state' AND record_key = ANY($1)
    ORDER BY record_key, policy_version DESC, seq DESC";

const COUNT_UNPUBLISHED: &str =
    "SELECT count(*) FROM iam_outbox WHERE kind = 'state' AND published_at IS NULL";

/// The row goes back to the unpublished rows; a row that is not published is left as it is.
const CLEAR_MARKS: &str = "UPDATE iam_outbox
    SET published_at = NULL, published_offset = NULL, relay_epoch = NULL
    WHERE id = $1 AND published_at IS NOT NULL";

/// A stored value that no domain value can describe.
#[derive(Debug, thiserror::Error)]
enum UnusableRow {
    /// A count or an offset is negative.
    #[error("the anti-entropy read holds a negative number")]
    Negative,
}

impl PgAntiEntropyStore {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_head(&self) -> Result<StoredHead, RepositoryError> {
        let row = sqlx::query(SELECT_HEAD)
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
            .ok_or(RepositoryError::NotFound)?;
        head_of(&row)
    }

    async fn select_recent(
        &self,
        since: SystemTime,
        limit: u32,
    ) -> Result<Vec<PublishedRecord>, RepositoryError> {
        let rows = sqlx::query(RECENTLY_PUBLISHED)
            .bind(timestamp(since)?)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        rows.iter().map(published_of).collect()
    }

    async fn select_written(&self, since: SystemTime) -> Result<Vec<WrittenKey>, RepositoryError> {
        let rows = sqlx::query(WRITTEN_SINCE)
            .bind(timestamp(since)?)
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        rows.iter().map(written_of).collect()
    }

    async fn select_newest(&self, keys: &[String]) -> Result<Vec<WrittenKey>, RepositoryError> {
        let rows = sqlx::query(NEWEST_OF_KEYS)
            .bind(keys)
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        rows.iter().map(written_of).collect()
    }

    async fn count_unpublished(&self) -> Result<u64, RepositoryError> {
        let count: i64 = sqlx::query_scalar(COUNT_UNPUBLISHED)
            .fetch_one(&self.pool)
            .await
            .map_err(unavailable)?;
        count_of(count)
    }

    async fn clear_marks(&self, id: Uuid) -> Result<bool, RepositoryError> {
        let cleared = sqlx::query(CLEAR_MARKS)
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(cleared.rows_affected() > 0)
    }
}

fn head_of(row: &PgRow) -> Result<StoredHead, RepositoryError> {
    let version: i64 = row.try_get("version").map_err(unavailable)?;
    let digest: Vec<u8> = row.try_get("digest").map_err(unavailable)?;
    Ok(StoredHead {
        version: PolicyVersion::new(version).map_err(unusable)?,
        digest: PolicyDigestValue::new(&digest).map_err(unusable)?,
    })
}

fn published_of(row: &PgRow) -> Result<PublishedRecord, RepositoryError> {
    let id: SqlUuid = row.try_get("id").map_err(unavailable)?;
    let version: i64 = row.try_get("policy_version").map_err(unavailable)?;
    let offset: i64 = row.try_get("published_offset").map_err(unavailable)?;
    Ok(PublishedRecord {
        id: Uuid::from_uuid(id),
        key: row.try_get("record_key").map_err(unavailable)?,
        version: PolicyVersion::new(version).map_err(unusable)?,
        offset,
    })
}

fn written_of(row: &PgRow) -> Result<WrittenKey, RepositoryError> {
    let id: SqlUuid = row.try_get("id").map_err(unavailable)?;
    let version: i64 = row.try_get("policy_version").map_err(unavailable)?;
    let offset: Option<i64> = row.try_get("published_offset").map_err(unavailable)?;
    Ok(WrittenKey {
        id: Uuid::from_uuid(id),
        key: row.try_get("record_key").map_err(unavailable)?,
        version: PolicyVersion::new(version).map_err(unusable)?,
        published_offset: offset,
    })
}

/// A stored count as an unsigned number; a negative count is unusable data.
fn count_of(count: i64) -> Result<u64, RepositoryError> {
    u64::try_from(count).map_err(|_error| negative())
}

fn negative() -> RepositoryError {
    RepositoryError::Unavailable(Box::new(UnusableRow::Negative))
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl AntiEntropyStore for PgAntiEntropyStore {
    async fn head(&self) -> Result<StoredHead, RepositoryError> {
        self.select_head().await
    }

    async fn recently_published(
        &self,
        since: SystemTime,
        limit: u32,
    ) -> Result<Vec<PublishedRecord>, RepositoryError> {
        self.select_recent(since, limit).await
    }

    async fn keys_written_since(
        &self,
        since: SystemTime,
    ) -> Result<Vec<WrittenKey>, RepositoryError> {
        self.select_written(since).await
    }

    async fn newest_rows(&self, keys: &[String]) -> Result<Vec<WrittenKey>, RepositoryError> {
        self.select_newest(keys).await
    }

    async fn unpublished_count(&self) -> Result<u64, RepositoryError> {
        self.count_unpublished().await
    }

    async fn republish(&self, id: Uuid) -> Result<bool, RepositoryError> {
        self.clear_marks(id).await
    }
}

#[cfg(test)]
mod tests;
