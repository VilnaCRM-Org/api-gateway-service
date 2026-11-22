//! PostgreSQL implementation of the revocation repository port: session revocations, user and
//! global cut-offs, and the once-per-event record of consumed User service events.

use std::time::{SystemTime, UNIX_EPOCH};

use iam_domain::{
    ActorRef, GlobalTokenCutoff, InboundEvent, InvalidIamValue, RepositoryError,
    RevocationRepository, RevocationSource, SessionId, SessionRevocation, SessionRevocationId,
    UserTokenCutoff,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

/// Writes and reads `iam_revoked_sessions`, `iam_user_token_validity`, `iam_global_token_cutoff`
/// and `iam_inbound_events`.
#[derive(Debug)]
pub struct PgRevocationRepository {
    pool: sqlx::PgPool,
}

/// A stored session revocation; it never leaves this module.
struct SessionRow {
    session_id: String,
    id: SqlUuid,
    user_id: SqlUuid,
    source: String,
    revoked_by: String,
    revoked_at: OffsetDateTime,
    prune_after: OffsetDateTime,
}

/// A stored user cut-off; it never leaves this module.
struct UserCutoffRow {
    user_id: SqlUuid,
    tokens_valid_after: OffsetDateTime,
    source: String,
    updated_at: OffsetDateTime,
    prune_after: OffsetDateTime,
}

/// The stored global cut-off; it never leaves this module.
struct GlobalCutoffRow {
    tokens_valid_after: OffsetDateTime,
    set_by: String,
    set_at: OffsetDateTime,
}

impl PgRevocationRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Inserts the session revocation. The text values travel as one `text[]` parameter in the
    /// order session id, source and revoker, and the times as one `timestamptz[]` in the order
    /// revoked at and prune after, which keeps the parameter list short.
    async fn insert_session(&self, revocation: &SessionRevocation) -> Result<(), RepositoryError> {
        let texts = [
            revocation.session.as_str().to_owned(),
            revocation.source.as_str().to_owned(),
            revocation.revoked_by.to_string(),
        ];
        let times = [
            timestamp(revocation.revoked_at)?,
            timestamp(revocation.prune_after)?,
        ];
        sqlx::query!(
            "INSERT INTO iam_revoked_sessions
                (session_id, id, user_id, source, revoked_by, revoked_at, prune_after)
            VALUES (($3::text[])[1], $1, $2, ($3::text[])[2], ($3::text[])[3],
                ($4::timestamptz[])[1], ($4::timestamptz[])[2])
            ON CONFLICT (session_id) DO NOTHING",
            revocation.id.as_uuid().as_uuid(),
            revocation.user.as_uuid(),
            texts.as_slice(),
            times.as_slice(),
        )
        .execute(&self.pool)
        .await
        .map_err(translate)?;
        Ok(())
    }

    async fn upsert_user_cutoff(&self, cutoff: &UserTokenCutoff) -> Result<(), RepositoryError> {
        sqlx::query!(
            "INSERT INTO iam_user_token_validity
                (user_id, tokens_valid_after, source, updated_at, prune_after)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id) DO UPDATE SET
                tokens_valid_after = EXCLUDED.tokens_valid_after,
                source = EXCLUDED.source,
                updated_at = EXCLUDED.updated_at,
                prune_after = GREATEST(iam_user_token_validity.prune_after, EXCLUDED.prune_after)
            WHERE EXCLUDED.tokens_valid_after > iam_user_token_validity.tokens_valid_after",
            cutoff.user.as_uuid(),
            timestamp(cutoff.tokens_valid_after)?,
            cutoff.source.as_str(),
            timestamp(cutoff.updated_at)?,
            timestamp(cutoff.prune_after)?,
        )
        .execute(&self.pool)
        .await
        .map_err(translate)?;
        Ok(())
    }

    async fn upsert_global_cutoff(
        &self,
        cutoff: &GlobalTokenCutoff,
    ) -> Result<(), RepositoryError> {
        sqlx::query!(
            "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at)
            VALUES (1, $1, $2, $3)
            ON CONFLICT (id) DO UPDATE SET
                tokens_valid_after = EXCLUDED.tokens_valid_after,
                set_by = EXCLUDED.set_by,
                set_at = EXCLUDED.set_at
            WHERE EXCLUDED.tokens_valid_after > iam_global_token_cutoff.tokens_valid_after",
            timestamp(cutoff.tokens_valid_after)?,
            cutoff.set_by.to_string(),
            timestamp(cutoff.set_at)?,
        )
        .execute(&self.pool)
        .await
        .map_err(translate)?;
        Ok(())
    }

    async fn select_session(
        &self,
        session: &SessionId,
    ) -> Result<Option<SessionRevocation>, RepositoryError> {
        let row = sqlx::query_as!(
            SessionRow,
            "SELECT session_id, id, user_id, source, revoked_by, revoked_at, prune_after
            FROM iam_revoked_sessions WHERE session_id = $1",
            session.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.as_ref().map(restore_session).transpose()
    }

    async fn select_user_cutoff(
        &self,
        user: Uuid,
    ) -> Result<Option<UserTokenCutoff>, RepositoryError> {
        let row = sqlx::query_as!(
            UserCutoffRow,
            "SELECT user_id, tokens_valid_after, source, updated_at, prune_after
            FROM iam_user_token_validity WHERE user_id = $1",
            user.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.as_ref().map(restore_user_cutoff).transpose()
    }

    async fn select_global_cutoff(&self) -> Result<Option<GlobalTokenCutoff>, RepositoryError> {
        let row = sqlx::query_as!(
            GlobalCutoffRow,
            "SELECT tokens_valid_after, set_by, set_at FROM iam_global_token_cutoff WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.as_ref().map(restore_global_cutoff).transpose()
    }

    /// Records the consumed event once. The text values travel as one `text[]` parameter in the
    /// order topic, event type and outcome, and the position as one `bigint[]` in the order
    /// partition and offset, which keeps the parameter list short.
    async fn insert_inbound_event(&self, event: &InboundEvent) -> Result<bool, RepositoryError> {
        let texts = [
            event.topic.clone(),
            event.event_type.clone(),
            event.outcome.as_str().to_owned(),
        ];
        let position = [i64::from(event.partition), event.offset];
        let processed_at = timestamp(event.processed_at)?;
        let inserted = sqlx::query!(
            r#"INSERT INTO iam_inbound_events
                (event_id, topic, partition, "offset", event_type, outcome, error, processed_at)
            VALUES ($1, ($2::text[])[1], ($3::bigint[])[1], ($3::bigint[])[2], ($2::text[])[2],
                ($2::text[])[3], $4, $5)
            ON CONFLICT (event_id) DO NOTHING"#,
            event.event_id.as_uuid(),
            texts.as_slice(),
            position.as_slice(),
            event.error.as_deref(),
            processed_at,
        )
        .execute(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(inserted.rows_affected() == 1)
    }
}

/// The `timestamptz` value of a time; a time before 1970 or after the year 9999 cannot be stored.
pub(crate) fn timestamp(time: SystemTime) -> Result<OffsetDateTime, RepositoryError> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i128::try_from(elapsed.as_nanos()).ok())
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .ok_or_else(|| unusable(InvalidIamValue::AuditTimestamp))
}

/// The `SystemTime` of a stored `timestamptz` value.
pub(crate) fn system_time(value: OffsetDateTime) -> SystemTime {
    SystemTime::from(value)
}

/// A unique violation is a record that already exists; everything else, a pool acquire timeout
/// included, is an unavailable repository.
fn translate(error: sqlx::Error) -> RepositoryError {
    let unique = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    if unique {
        RepositoryError::AlreadyExists
    } else {
        unavailable(error)
    }
}

/// A failed statement or an unreachable database is an unavailable repository.
pub(crate) fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds the session revocation of the stored row through the value objects.
fn restore_session(row: &SessionRow) -> Result<SessionRevocation, RepositoryError> {
    let session = SessionId::new(&row.session_id)
        .map_err(|rejection| RepositoryError::Unavailable(Box::new(rejection)))?;
    Ok(SessionRevocation {
        id: SessionRevocationId::from_uuid(Uuid::from_uuid(row.id)),
        session,
        user: Uuid::from_uuid(row.user_id),
        source: RevocationSource::parse(&row.source).map_err(unusable)?,
        revoked_by: ActorRef::parse(&row.revoked_by).map_err(unusable)?,
        revoked_at: system_time(row.revoked_at),
        prune_after: system_time(row.prune_after),
    })
}

/// Rebuilds the user cut-off of the stored row through the value objects.
fn restore_user_cutoff(row: &UserCutoffRow) -> Result<UserTokenCutoff, RepositoryError> {
    Ok(UserTokenCutoff {
        user: Uuid::from_uuid(row.user_id),
        tokens_valid_after: system_time(row.tokens_valid_after),
        source: RevocationSource::parse(&row.source).map_err(unusable)?,
        updated_at: system_time(row.updated_at),
        prune_after: system_time(row.prune_after),
    })
}

/// Rebuilds the global cut-off of the stored row through the value objects.
fn restore_global_cutoff(row: &GlobalCutoffRow) -> Result<GlobalTokenCutoff, RepositoryError> {
    Ok(GlobalTokenCutoff {
        tokens_valid_after: system_time(row.tokens_valid_after),
        set_by: ActorRef::parse(&row.set_by).map_err(unusable)?,
        set_at: system_time(row.set_at),
    })
}

#[async_trait::async_trait]
impl RevocationRepository for PgRevocationRepository {
    async fn revoke_session(&self, revocation: &SessionRevocation) -> Result<(), RepositoryError> {
        self.insert_session(revocation).await
    }

    async fn set_user_cutoff(&self, cutoff: &UserTokenCutoff) -> Result<(), RepositoryError> {
        self.upsert_user_cutoff(cutoff).await
    }

    async fn set_global_cutoff(&self, cutoff: &GlobalTokenCutoff) -> Result<(), RepositoryError> {
        self.upsert_global_cutoff(cutoff).await
    }

    async fn session_revocation(
        &self,
        session: &SessionId,
    ) -> Result<Option<SessionRevocation>, RepositoryError> {
        self.select_session(session).await
    }

    async fn user_cutoff(&self, user: Uuid) -> Result<Option<UserTokenCutoff>, RepositoryError> {
        self.select_user_cutoff(user).await
    }

    async fn global_cutoff(&self) -> Result<Option<GlobalTokenCutoff>, RepositoryError> {
        self.select_global_cutoff().await
    }

    async fn record_inbound_event(&self, event: &InboundEvent) -> Result<bool, RepositoryError> {
        self.insert_inbound_event(event).await
    }
}

#[cfg(test)]
mod tests;
