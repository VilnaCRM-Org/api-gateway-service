//! PostgreSQL implementation of the propagation store port: the stored offset of the `__head` row
//! of a policy version and the propagation outcome of a change receipt.
//!
//! The statements are checked at run time, so the offline metadata does not hold them.

use iam_domain::{ChangeId, PolicyVersion, PropagationOutcome, PropagationStore, RepositoryError};
use sqlx::Row as _;

/// The offset of the `__head` state row of a version, once the relay marked it published.
const HEAD_OFFSET: &str = "SELECT published_offset FROM iam_outbox
    WHERE kind = 'state' AND record_key = '__head' AND policy_version = $1
        AND published_at IS NOT NULL
    ORDER BY seq DESC NULLS LAST
    LIMIT 1";

const RECORD: &str = "UPDATE iam_change_receipts
    SET propagation_status = $2, propagation_offset = $3
    WHERE change_id = $1";

/// The stored propagation columns of one receipt.
pub(crate) const SELECT_PROPAGATION: &str =
    "SELECT propagation_status, propagation_offset FROM iam_change_receipts WHERE change_id = $1";

/// Reads the offsets that the relay stored and writes the propagation outcome of the receipts.
#[derive(Debug)]
pub struct PgPropagationStore {
    pool: sqlx::PgPool,
}

impl PgPropagationStore {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn head_offset(&self, version: PolicyVersion) -> Result<Option<i64>, RepositoryError> {
        let row = sqlx::query(HEAD_OFFSET)
            .bind(version.value())
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?;
        row.map(|row| row.try_get::<Option<i64>, _>("published_offset"))
            .transpose()
            .map(Option::flatten)
            .map_err(unavailable)
    }

    async fn store(
        &self,
        change_id: ChangeId,
        outcome: PropagationOutcome,
    ) -> Result<(), RepositoryError> {
        let written = sqlx::query(RECORD)
            .bind(change_id.as_uuid().as_uuid())
            .bind(outcome.status())
            .bind(outcome.offset())
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        if written.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }
}

/// Any failure of the storage is an unavailable repository.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl PropagationStore for PgPropagationStore {
    async fn published_head_offset(
        &self,
        version: PolicyVersion,
    ) -> Result<Option<i64>, RepositoryError> {
        self.head_offset(version).await
    }

    async fn record(
        &self,
        change_id: ChangeId,
        outcome: PropagationOutcome,
    ) -> Result<(), RepositoryError> {
        self.store(change_id, outcome).await
    }
}

#[cfg(test)]
mod tests;
