//! The wake-up of the outbox relay: a `LISTEN iam_outbox` connection that reports each
//! `pg_notify('iam_outbox', '')` of a committed change (FR-46).
//!
//! A notification carries no keys and is only a hint: the relay still polls, so a notification
//! that is lost while the connection is re-established costs at most one poll interval.

use iam_domain::RepositoryError;
use sqlx::postgres::PgListener;

/// The channel that `PgIamUnitOfWork` notifies after it wrote outbox rows.
pub const OUTBOX_CHANNEL: &str = "iam_outbox";

/// A connection that listens on [`OUTBOX_CHANNEL`].
#[derive(Debug)]
pub struct PgOutboxListener {
    listener: PgListener,
}

impl PgOutboxListener {
    /// Takes a connection of `pool`, which should not be pooled behind a transaction-mode proxy,
    /// and listens on the channel of the outbox.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the connection or the `LISTEN` fails.
    pub async fn connect(pool: &sqlx::PgPool) -> Result<Self, RepositoryError> {
        let mut listener = PgListener::connect_with(pool).await.map_err(unavailable)?;
        listener.listen(OUTBOX_CHANNEL).await.map_err(unavailable)?;
        Ok(Self { listener })
    }

    /// Waits for the next notification of a committed change.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the connection is lost and cannot be re-established.
    pub async fn notified(&mut self) -> Result<(), RepositoryError> {
        self.listener
            .recv()
            .await
            .map(|_notification| ())
            .map_err(unavailable)
    }
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}
