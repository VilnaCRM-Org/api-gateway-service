//! PostgreSQL implementation of the singleton leadership port: a transaction-level advisory lock
//! that is tried without waiting at the start of every batch.

use std::time::SystemTime;

use iam_domain::{LeaderBatch, Leadership, RepositoryError, SingletonLeadership, SingletonTask};
use sqlx::types::time::OffsetDateTime;
use sqlx::{Postgres, Transaction};

/// Opens each singleton batch with `pg_try_advisory_xact_lock(<task constant>)` in a transaction.
///
/// The lock lives and dies with that transaction, so a batch that ends, fails or loses
/// its connection (a terminated backend, a dead replica) frees the leadership and rolls its writes
/// back.
#[derive(Debug)]
pub struct AdvisoryLockLeadership {
    pool: sqlx::PgPool,
}

/// The open transaction of a batch that this replica leads.
#[derive(Debug)]
struct PgLeaderBatch {
    task: SingletonTask,
    transaction: Transaction<'static, Postgres>,
}

const RECORD_RUN: &str = "INSERT INTO iam_task_state (task_name, last_run_at, run_count) \
    VALUES ($1, $2, 1) \
    ON CONFLICT (task_name) DO UPDATE \
    SET last_run_at = EXCLUDED.last_run_at, run_count = iam_task_state.run_count + 1";

const TRY_LOCK: &str = "SELECT pg_try_advisory_xact_lock($1)";

impl AdvisoryLockLeadership {
    /// Builds the leadership over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn open(&self, task: &SingletonTask) -> Result<Leadership, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let leads: bool = sqlx::query_scalar(TRY_LOCK)
            .bind(task.lock_key())
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
        if !leads {
            transaction.rollback().await.map_err(unavailable)?;
            return Ok(Leadership::Follower);
        }
        Ok(Leadership::Leader(Box::new(PgLeaderBatch {
            task: *task,
            transaction,
        })))
    }
}

impl PgLeaderBatch {
    async fn write_run(&mut self, at: SystemTime) -> Result<(), RepositoryError> {
        sqlx::query(RECORD_RUN)
            .bind(self.task.name())
            .bind(OffsetDateTime::from(at))
            .execute(&mut *self.transaction)
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    async fn end_with_commit(self) -> Result<(), RepositoryError> {
        self.transaction.commit().await.map_err(unavailable)
    }

    async fn end_with_rollback(self) -> Result<(), RepositoryError> {
        self.transaction.rollback().await.map_err(unavailable)
    }
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl LeaderBatch for PgLeaderBatch {
    async fn record_run(&mut self, at: SystemTime) -> Result<(), RepositoryError> {
        self.write_run(at).await
    }

    async fn commit(self: Box<Self>) -> Result<(), RepositoryError> {
        self.end_with_commit().await
    }

    async fn rollback(self: Box<Self>) -> Result<(), RepositoryError> {
        self.end_with_rollback().await
    }
}

#[async_trait::async_trait]
impl SingletonLeadership for AdvisoryLockLeadership {
    async fn begin(&self, task: &SingletonTask) -> Result<Leadership, RepositoryError> {
        self.open(task).await
    }
}

#[cfg(test)]
mod tests;
