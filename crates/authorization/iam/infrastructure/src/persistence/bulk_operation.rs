//! PostgreSQL implementation of the bulk operation repository port: the `iam_bulk_operations`
//! table.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    ActorRef, BulkKind, BulkOperation, BulkOperationId, BulkOperationParts,
    BulkOperationRepository, BulkProgressStatement, BulkStatus, PolicyVersion, RepositoryError,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::role::{translate, updated};
use crate::persistence::stored::{unusable_field, unusable_value};

/// A statement that selects the columns of a bulk operation row, followed by `$tail`.
macro_rules! select {
    ($tail:literal) => {
        concat!(
            "SELECT id, kind, status, total_records, applied_records, first_version, last_version,
                requester, error, created_at, updated_at
            FROM iam_bulk_operations ",
            $tail
        )
    };
}

const INSERT: &str = "INSERT INTO iam_bulk_operations (id, kind, status, total_records,
        applied_records, first_version, last_version, requester, error, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

const UPDATE: &str = "UPDATE iam_bulk_operations
    SET status = $2, applied_records = $3, first_version = $4, last_version = $5, error = $6,
        updated_at = $7
    WHERE id = $1";

const UPDATE_PROGRESS: &str = "UPDATE iam_bulk_operations
    SET status = $2, applied_records = $3, first_version = $4, last_version = $5, updated_at = $6
    WHERE id = $1 AND applied_records = $7 AND status IN ('pending', 'running')";

/// Stores the progress of a bulk operation inside the transaction of a chunk's change.
///
/// # Errors
///
/// [`RepositoryError::Conflict`] when the stored operation is finished or has not applied the
/// expected records, and [`RepositoryError::Unavailable`] when the storage fails or a value cannot
/// be stored.
pub async fn save_progress_within(
    connection: &mut PgConnection,
    statement: &BulkProgressStatement,
) -> Result<(), RepositoryError> {
    let parts = statement.operation();
    let done = sqlx::query(UPDATE_PROGRESS)
        .bind(parts.id.as_uuid().as_uuid())
        .bind(parts.status.as_str())
        .bind(count(parts.applied_records)?)
        .bind(parts.first_version.map(PolicyVersion::value))
        .bind(parts.last_version.map(PolicyVersion::value))
        .bind(OffsetDateTime::from(parts.updated_at))
        .bind(count(statement.expected_applied())?)
        .execute(&mut *connection)
        .await
        .map_err(translate)?;
    updated(done.rows_affected())
}

/// The stored bulk operation row; it never leaves this module.
#[derive(sqlx::FromRow)]
struct BulkOperationRow {
    id: SqlUuid,
    kind: String,
    status: String,
    total_records: i64,
    applied_records: i64,
    first_version: Option<i64>,
    last_version: Option<i64>,
    requester: String,
    error: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Stores the bulk operations and their progress.
#[derive(Debug)]
pub struct PgBulkOperationRepository {
    pool: sqlx::PgPool,
}

impl PgBulkOperationRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn insert_row(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        let parts = operation.parts();
        sqlx::query(INSERT)
            .bind(parts.id.as_uuid().as_uuid())
            .bind(parts.kind.as_str())
            .bind(parts.status.as_str())
            .bind(count(parts.total_records)?)
            .bind(count(parts.applied_records)?)
            .bind(parts.first_version.map(PolicyVersion::value))
            .bind(parts.last_version.map(PolicyVersion::value))
            .bind(parts.requester.to_string())
            .bind(parts.error.as_deref())
            .bind(OffsetDateTime::from(parts.created_at))
            .bind(OffsetDateTime::from(parts.updated_at))
            .execute(&self.pool)
            .await
            .map_err(translate)?;
        Ok(())
    }

    async fn update_row(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        let parts = operation.parts();
        let done = sqlx::query(UPDATE)
            .bind(parts.id.as_uuid().as_uuid())
            .bind(parts.status.as_str())
            .bind(count(parts.applied_records)?)
            .bind(parts.first_version.map(PolicyVersion::value))
            .bind(parts.last_version.map(PolicyVersion::value))
            .bind(parts.error.as_deref())
            .bind(OffsetDateTime::from(parts.updated_at))
            .execute(&self.pool)
            .await
            .map_err(translate)?;
        updated(done.rows_affected()).map_err(|_conflict| RepositoryError::NotFound)
    }

    async fn find_row(
        &self,
        id: BulkOperationId,
    ) -> Result<Option<BulkOperation>, RepositoryError> {
        let row = sqlx::query_as::<_, BulkOperationRow>(select!("WHERE id = $1"))
            .bind(id.as_uuid().as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(translate)?;
        row.map(restore).transpose()
    }

    async fn list_rows(
        &self,
        after: Option<BulkOperationId>,
        limit: u32,
    ) -> Result<Vec<BulkOperation>, RepositoryError> {
        let after = after.map(|id| id.as_uuid().as_uuid());
        let rows = sqlx::query_as::<_, BulkOperationRow>(select!(
            "WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
        ))
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        rows.into_iter().map(restore).collect()
    }

    async fn oldest_unfinished_row(&self) -> Result<Option<BulkOperation>, RepositoryError> {
        let row = sqlx::query_as::<_, BulkOperationRow>(select!(
            "WHERE status IN ('pending', 'running') ORDER BY id LIMIT 1"
        ))
        .fetch_optional(&self.pool)
        .await
        .map_err(translate)?;
        row.map(restore).transpose()
    }
}

/// A count as the stored `BIGINT`; a count above its range is unusable data.
fn count(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_error| unusable_field("records"))
}

/// A stored `BIGINT` count; a negative one is unusable data.
fn records(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_error| unusable_field("records"))
}

/// A stored version; a negative one is unusable data.
fn version(value: Option<i64>) -> Result<Option<PolicyVersion>, RepositoryError> {
    value
        .map(|value| PolicyVersion::new(value).map_err(unusable_value))
        .transpose()
}

/// Rebuilds the operation of a stored row; a value the domain refuses is unusable data.
fn restore(row: BulkOperationRow) -> Result<BulkOperation, RepositoryError> {
    BulkOperation::restore(BulkOperationParts {
        id: BulkOperationId::from_uuid(Uuid::from_uuid(row.id)),
        kind: BulkKind::parse(&row.kind).map_err(unusable_value)?,
        status: BulkStatus::parse(&row.status).map_err(unusable_value)?,
        total_records: records(row.total_records)?,
        applied_records: records(row.applied_records)?,
        first_version: version(row.first_version)?,
        last_version: version(row.last_version)?,
        requester: ActorRef::parse(&row.requester).map_err(unusable_value)?,
        error: row.error,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
    })
    .map_err(unusable_value)
}

#[async_trait::async_trait]
impl BulkOperationRepository for PgBulkOperationRepository {
    async fn insert(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        self.insert_row(operation).await
    }

    async fn save(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        self.update_row(operation).await
    }

    async fn find(&self, id: BulkOperationId) -> Result<Option<BulkOperation>, RepositoryError> {
        self.find_row(id).await
    }

    async fn list(
        &self,
        after: Option<BulkOperationId>,
        limit: u32,
    ) -> Result<Vec<BulkOperation>, RepositoryError> {
        self.list_rows(after, limit).await
    }

    async fn oldest_unfinished(&self) -> Result<Option<BulkOperation>, RepositoryError> {
        self.oldest_unfinished_row().await
    }
}

#[cfg(test)]
mod tests;
