//! PostgreSQL implementation of the idempotency repository port: reads `iam_idempotency_keys`,
//! which the unit of work writes.

use std::time::{SystemTime, UNIX_EPOCH};

use iam_domain::{
    ActorRef, ChangeId, IdempotencyKey, IdempotencyRecord, IdempotencyRepository,
    IdempotencyRequest, InvalidIamValue, RepositoryError, RequestDigest,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

/// Reads the idempotency records from the `iam_idempotency_keys` table.
#[derive(Debug)]
pub struct PgIdempotencyRepository {
    pool: sqlx::PgPool,
}

/// The stored row; it never leaves this module.
struct Row {
    request_digest: Vec<u8>,
    change_id: SqlUuid,
}

impl PgIdempotencyRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_since(
        &self,
        actor: &ActorRef,
        key: &IdempotencyKey,
        since: SystemTime,
    ) -> Result<Option<IdempotencyRecord>, RepositoryError> {
        let row = sqlx::query_as!(
            Row,
            "SELECT request_digest, change_id FROM iam_idempotency_keys
            WHERE actor = $1 AND idempotency_key = $2 AND created_at >= $3",
            actor.to_string(),
            key.as_str(),
            timestamp(since)?,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| RepositoryError::Unavailable(Box::new(error)))?;
        row.map(|row| restore(actor, key, &row)).transpose()
    }
}

/// The `timestamptz` value of a time; a time before 1970 or after the year 9999 cannot be
/// compared with the stored creation times.
fn timestamp(time: SystemTime) -> Result<OffsetDateTime, RepositoryError> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i128::try_from(elapsed.as_nanos()).ok())
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .ok_or_else(|| RepositoryError::Unavailable(Box::new(InvalidIamValue::AuditTimestamp)))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds the record of the stored row through the value objects.
fn restore(
    actor: &ActorRef,
    key: &IdempotencyKey,
    row: &Row,
) -> Result<IdempotencyRecord, RepositoryError> {
    let request = IdempotencyRequest {
        key: key.clone(),
        request_digest: RequestDigest::new(&row.request_digest).map_err(unusable)?,
    };
    let change_id = ChangeId::from_uuid(Uuid::from_uuid(row.change_id));
    Ok(IdempotencyRecord::new(actor.clone(), request, change_id))
}

#[async_trait::async_trait]
impl IdempotencyRepository for PgIdempotencyRepository {
    async fn find_since(
        &self,
        actor: &ActorRef,
        key: &IdempotencyKey,
        since: SystemTime,
    ) -> Result<Option<IdempotencyRecord>, RepositoryError> {
        self.select_since(actor, key, since).await
    }
}

#[cfg(test)]
mod tests;
