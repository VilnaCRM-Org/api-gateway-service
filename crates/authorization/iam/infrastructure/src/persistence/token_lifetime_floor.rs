//! PostgreSQL implementation of the token lifetime floor port: the single row of
//! `iam_token_lifetime_floor` that keeps the longest `MAX_TOKEN_LIFETIME` ever configured.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use std::time::Duration;

use iam_domain::{InvalidIamValue, RepositoryError, TokenLifetimeFloor};

use crate::persistence::revocation::unavailable;

/// Reads and raises the floor row.
#[derive(Debug)]
pub struct PgTokenLifetimeFloor {
    pool: sqlx::PgPool,
}

impl PgTokenLifetimeFloor {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn raise(&self, configured: Duration) -> Result<Duration, RepositoryError> {
        let seconds = i64::try_from(configured.as_secs()).map_err(|_error| out_of_range())?;
        let stored = sqlx::query_scalar::<_, i64>(
            "INSERT INTO iam_token_lifetime_floor (id, longest_lifetime_seconds, updated_at)
            VALUES (1, $1, now())
            ON CONFLICT (id) DO UPDATE SET
                longest_lifetime_seconds = GREATEST(
                    iam_token_lifetime_floor.longest_lifetime_seconds,
                    EXCLUDED.longest_lifetime_seconds),
                updated_at = CASE
                    WHEN EXCLUDED.longest_lifetime_seconds
                        > iam_token_lifetime_floor.longest_lifetime_seconds
                    THEN now() ELSE iam_token_lifetime_floor.updated_at END
            RETURNING longest_lifetime_seconds",
        )
        .bind(seconds)
        .fetch_one(&self.pool)
        .await
        .map_err(unavailable)?;
        lifetime_of(stored)
    }

    async fn select(&self) -> Result<Option<Duration>, RepositoryError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT longest_lifetime_seconds FROM iam_token_lifetime_floor WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .map(lifetime_of)
        .transpose()
    }
}

/// The lifetime of a stored number of seconds; a value that is not positive is unusable data.
fn lifetime_of(seconds: i64) -> Result<Duration, RepositoryError> {
    u64::try_from(seconds)
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .ok_or_else(out_of_range)
}

/// A lifetime that does not fit the column, or a stored value that is not positive.
fn out_of_range() -> RepositoryError {
    RepositoryError::Unavailable(Box::new(InvalidIamValue::AuditTimestamp))
}

#[async_trait::async_trait]
impl TokenLifetimeFloor for PgTokenLifetimeFloor {
    async fn raise_to(&self, configured: Duration) -> Result<Duration, RepositoryError> {
        self.raise(configured).await
    }

    async fn longest(&self) -> Result<Option<Duration>, RepositoryError> {
        self.select().await
    }
}

#[cfg(test)]
mod tests;
