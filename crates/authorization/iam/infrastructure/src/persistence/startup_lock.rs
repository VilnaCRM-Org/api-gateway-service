//! PostgreSQL implementation of the startup lock port: a transaction-level advisory lock.

use iam_domain::{LockGuard, RepositoryError, StartupLock};
use sqlx::{Postgres, Transaction};

/// Takes `pg_advisory_xact_lock` on the hash of the lock name inside a transaction that it keeps
/// open until the guard is dropped, so the lock is released with the transaction even when the
/// instance dies.
#[derive(Debug)]
pub struct PgStartupLock {
    pool: sqlx::PgPool,
}

/// The open transaction that holds the lock; dropping it rolls the transaction back.
#[derive(Debug)]
struct PgLockGuard {
    _transaction: Transaction<'static, Postgres>,
}

impl LockGuard for PgLockGuard {}

impl PgStartupLock {
    /// Builds the lock over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn take(&self, name: &str) -> Result<Box<dyn LockGuard>, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(name)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        Ok(Box::new(PgLockGuard {
            _transaction: transaction,
        }))
    }
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl StartupLock for PgStartupLock {
    async fn acquire(&self, name: &str) -> Result<Box<dyn LockGuard>, RepositoryError> {
        self.take(name).await
    }
}

#[cfg(test)]
mod tests;
