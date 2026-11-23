//! PostgreSQL implementation of the outbox store port: the claim of the unpublished rows, the
//! takeover of the relay, the marks that are fenced by the relay epoch and the cleanup.
//!
//! The statements are checked at run time, so the offline metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    InvalidIamValue, LogEpoch, OutboxKind, OutboxRow, OutboxStore, PolicyDigestValue,
    PolicyVersion, PublishedRow, RelayEpoch, RelayTakeover, RepositoryError,
};
use shared_domain::Uuid;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid as SqlUuid;
use sqlx::{PgConnection, Row as _};

use crate::persistence::revocation::timestamp;

/// Reads and marks the rows of `iam_outbox`.
#[derive(Debug)]
pub struct PgOutboxStore {
    pool: sqlx::PgPool,
}

/// The unpublished rows in `(policy_version, seq)` order; the events of a version follow its state
/// rows and keep the order of their position.
const CLAIM: &str = "SELECT id, kind, topic, record_key, payload, policy_version, seq, count,
        digest_after, log_epoch, event_type
    FROM iam_outbox
    WHERE published_at IS NULL
    ORDER BY policy_version, seq NULLS LAST, position
    LIMIT $1";

const SELECT_EPOCH: &str = "SELECT relay_epoch FROM iam_policy_epoch WHERE id = 1";

/// The epoch is read under a share lock, so a takeover that is under way is waited for.
const LOCK_EPOCH: &str = "SELECT relay_epoch FROM iam_policy_epoch WHERE id = 1 FOR SHARE";

const INCREMENT_EPOCH: &str =
    "UPDATE iam_policy_epoch SET relay_epoch = relay_epoch + 1 WHERE id = 1 RETURNING relay_epoch";

/// The latest state row of every key, when it is published already: a key whose latest row is
/// still waiting is sent by the normal flow.
const LATEST_PUBLISHED_STATE: &str = "SELECT id, kind, topic, record_key, payload, policy_version,
        seq, count, digest_after, log_epoch, event_type
    FROM (
        SELECT DISTINCT ON (record_key) id, kind, topic, record_key, payload, policy_version,
            seq, count, digest_after, log_epoch, event_type, published_at
        FROM iam_outbox
        WHERE kind = 'state'
        ORDER BY record_key, policy_version DESC, seq DESC
    ) AS latest
    WHERE published_at IS NOT NULL
    ORDER BY policy_version, seq";

const MARK_PUBLISHED: &str = "UPDATE iam_outbox
    SET published_at = $1, published_offset = marks.published_offset, relay_epoch = $2
    FROM unnest($3::uuid[], $4::bigint[]) AS marks(id, published_offset)
    WHERE iam_outbox.id = marks.id";

const DELETE_PUBLISHED: &str =
    "DELETE FROM iam_outbox WHERE published_at IS NOT NULL AND published_at < $1";

/// A stored row that no domain value can describe.
#[derive(Debug, thiserror::Error)]
enum UnusableRow {
    /// The `kind` column holds neither `state` nor `event`.
    #[error("the outbox row has the unknown kind `{0}`")]
    Kind(String),
    /// A number of the framing is negative.
    #[error("the outbox row has a negative framing number")]
    Framing,
}

/// The values of a stored row before the domain checks them.
struct Stored {
    id: SqlUuid,
    kind: String,
    topic: String,
    record_key: String,
    payload: Option<String>,
    policy_version: i64,
    seq: Option<i32>,
    count: Option<i32>,
    digest_after: Option<Vec<u8>>,
    log_epoch: i64,
    event_type: Option<String>,
}

impl PgOutboxStore {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_unpublished(&self, limit: u32) -> Result<Vec<OutboxRow>, RepositoryError> {
        let rows = sqlx::query(CLAIM)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        rows.iter().map(row_of).collect()
    }

    async fn select_epoch(&self) -> Result<RelayEpoch, RepositoryError> {
        let epoch: i64 = sqlx::query_scalar(SELECT_EPOCH)
            .fetch_one(&self.pool)
            .await
            .map_err(unavailable)?;
        relay_epoch(epoch)
    }

    async fn increment_epoch(&self) -> Result<RelayTakeover, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let epoch: i64 = sqlx::query_scalar(INCREMENT_EPOCH)
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let republish = sqlx::query(LATEST_PUBLISHED_STATE)
            .fetch_all(&mut *transaction)
            .await
            .map_err(unavailable)?
            .iter()
            .map(row_of)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(RelayTakeover {
            epoch: relay_epoch(epoch)?,
            republish,
        })
    }

    async fn store_marks(
        &self,
        published: &[PublishedRow],
        epoch: RelayEpoch,
        at: SystemTime,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        ensure_current(&mut transaction, epoch).await?;
        let ids: Vec<SqlUuid> = published.iter().map(|row| row.id.as_uuid()).collect();
        let offsets: Vec<i64> = published.iter().map(|row| row.offset).collect();
        sqlx::query(MARK_PUBLISHED)
            .bind(timestamp(at)?)
            .bind(epoch.value())
            .bind(ids)
            .bind(offsets)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)
    }

    async fn remove_published(&self, before: SystemTime) -> Result<u64, RepositoryError> {
        let deleted = sqlx::query(DELETE_PUBLISHED)
            .bind(timestamp(before)?)
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(deleted.rows_affected())
    }
}

/// Fails with a conflict unless `epoch` is still the relay epoch; the epoch row stays locked for
/// sharing until the transaction ends, so no takeover slips in between the check and the marks.
async fn ensure_current(
    connection: &mut PgConnection,
    epoch: RelayEpoch,
) -> Result<(), RepositoryError> {
    let current: i64 = sqlx::query_scalar(LOCK_EPOCH)
        .fetch_one(connection)
        .await
        .map_err(unavailable)?;
    if current == epoch.value() {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

fn row_of(row: &PgRow) -> Result<OutboxRow, RepositoryError> {
    restore(Stored {
        id: row.try_get("id").map_err(unavailable)?,
        kind: row.try_get("kind").map_err(unavailable)?,
        topic: row.try_get("topic").map_err(unavailable)?,
        record_key: row.try_get("record_key").map_err(unavailable)?,
        payload: row.try_get("payload").map_err(unavailable)?,
        policy_version: row.try_get("policy_version").map_err(unavailable)?,
        seq: row.try_get("seq").map_err(unavailable)?,
        count: row.try_get("count").map_err(unavailable)?,
        digest_after: row.try_get("digest_after").map_err(unavailable)?,
        log_epoch: row.try_get("log_epoch").map_err(unavailable)?,
        event_type: row.try_get("event_type").map_err(unavailable)?,
    })
}

/// Rebuilds the row through the value objects.
fn restore(stored: Stored) -> Result<OutboxRow, RepositoryError> {
    Ok(OutboxRow {
        id: Uuid::from_uuid(stored.id),
        kind: kind_of(&stored.kind)?,
        topic: stored.topic,
        record_key: stored.record_key,
        payload: stored.payload,
        policy_version: PolicyVersion::new(stored.policy_version).map_err(unusable)?,
        seq: stored.seq.map(framing_number).transpose()?,
        count: stored.count.map(framing_number).transpose()?,
        digest_after: stored
            .digest_after
            .map(|bytes| PolicyDigestValue::new(&bytes))
            .transpose()
            .map_err(unusable)?,
        log_epoch: LogEpoch::new(stored.log_epoch).map_err(unusable)?,
        event_type: stored.event_type,
    })
}

fn kind_of(kind: &str) -> Result<OutboxKind, RepositoryError> {
    match kind {
        "state" => Ok(OutboxKind::State),
        "event" => Ok(OutboxKind::Event),
        other => Err(RepositoryError::Unavailable(Box::new(UnusableRow::Kind(
            other.to_owned(),
        )))),
    }
}

fn framing_number(value: i32) -> Result<u32, RepositoryError> {
    u32::try_from(value)
        .map_err(|_error| RepositoryError::Unavailable(Box::new(UnusableRow::Framing)))
}

fn relay_epoch(value: i64) -> Result<RelayEpoch, RepositoryError> {
    RelayEpoch::new(value).map_err(unusable)
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
impl OutboxStore for PgOutboxStore {
    async fn claim_unpublished(&self, limit: u32) -> Result<Vec<OutboxRow>, RepositoryError> {
        self.select_unpublished(limit).await
    }

    async fn current_relay_epoch(&self) -> Result<RelayEpoch, RepositoryError> {
        self.select_epoch().await
    }

    async fn take_over_relay(&self) -> Result<RelayTakeover, RepositoryError> {
        self.increment_epoch().await
    }

    async fn mark_published(
        &self,
        published: &[PublishedRow],
        epoch: RelayEpoch,
        at: SystemTime,
    ) -> Result<(), RepositoryError> {
        self.store_marks(published, epoch, at).await
    }

    async fn delete_published_before(&self, before: SystemTime) -> Result<u64, RepositoryError> {
        self.remove_published(before).await
    }
}

#[cfg(test)]
mod tests;
