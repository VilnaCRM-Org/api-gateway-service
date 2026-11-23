//! PostgreSQL implementation of the task state repository port: the `iam_task_state` table.

use std::time::SystemTime;

use iam_domain::{RepositoryError, TaskState, TaskStateRepository};
use sqlx::Row as _;
use sqlx::types::time::OffsetDateTime;

/// Reads what the committed batches of singleton tasks recorded.
#[derive(Debug)]
pub struct PgTaskStateRepository {
    pool: sqlx::PgPool,
}

const SELECT_STATE: &str = "SELECT last_run_at, run_count FROM iam_task_state WHERE task_name = $1";

impl PgTaskStateRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select(&self, name: &str) -> Result<Option<TaskState>, RepositoryError> {
        let row = sqlx::query(SELECT_STATE)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let last_run_at: OffsetDateTime = row.try_get(0).map_err(unavailable)?;
        let run_count: i64 = row.try_get(1).map_err(unavailable)?;
        restore(last_run_at, run_count).map(Some)
    }
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds the state of a stored row; a negative count is unusable data.
fn restore(last_run_at: OffsetDateTime, run_count: i64) -> Result<TaskState, RepositoryError> {
    let run_count =
        u64::try_from(run_count).map_err(|error| RepositoryError::Unavailable(Box::new(error)))?;
    Ok(TaskState {
        last_run_at: SystemTime::from(last_run_at),
        run_count,
    })
}

#[async_trait::async_trait]
impl TaskStateRepository for PgTaskStateRepository {
    async fn find(&self, name: &str) -> Result<Option<TaskState>, RepositoryError> {
        self.select(name).await
    }
}

#[cfg(test)]
mod tests;
