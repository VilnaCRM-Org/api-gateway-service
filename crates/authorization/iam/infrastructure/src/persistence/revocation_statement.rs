//! Runs the revocation statements that a change hands to the unit of work, and reads the state of
//! the revocation records for the versioned transaction.
//!
//! The statements and reads are checked at run time, so the offline query metadata does not hold
//! them.

use iam_domain::{
    ExpiredRevocation, GlobalRevocationState, GlobalTokenCutoff, InvalidIamValue, PolicyState,
    RepositoryError, RevocationStatement, SessionId, SessionRevocation, SessionRevocationState,
    UserRevocationState, UserTokenCutoff,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Row as _};

use crate::persistence::revocation::{system_time, timestamp};
use crate::persistence::role::translate;

/// Runs one revocation statement inside the caller's transaction.
///
/// A session that is already revoked keeps its first record, and a cut-off that is not later than
/// the stored one changes nothing. A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when another session's record has the same id and
/// [`RepositoryError::Unavailable`] when the storage fails.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &RevocationStatement,
) -> Result<(), RepositoryError> {
    match statement {
        RevocationStatement::Session(revocation) => insert_session(connection, revocation).await,
        RevocationStatement::UserCutoff(cutoff) => upsert_user_cutoff(connection, cutoff).await,
        RevocationStatement::GlobalCutoff(cutoff) => upsert_global_cutoff(connection, cutoff).await,
        RevocationStatement::Prune { target, now } => prune(connection, target, *now).await,
    }
}

/// Removes the record when its prune-after instant is still strictly before `now`; a cut-off that
/// was moved since it was read stays, and a record that is gone already changes nothing.
async fn prune(
    connection: &mut PgConnection,
    target: &ExpiredRevocation,
    now: std::time::SystemTime,
) -> Result<(), RepositoryError> {
    let query = match target {
        ExpiredRevocation::Session { session, .. } => sqlx::query(
            "DELETE FROM iam_revoked_sessions WHERE session_id = $1 AND prune_after < $2",
        )
        .bind(session.to_string()),
        ExpiredRevocation::UserCutoff { user, .. } => sqlx::query(
            "DELETE FROM iam_user_token_validity WHERE user_id = $1 AND prune_after < $2",
        )
        .bind(user.as_uuid()),
    };
    query
        .bind(timestamp(now)?)
        .execute(&mut *connection)
        .await
        .map(|_done| ())
        .map_err(translate)
}

async fn insert_session(
    connection: &mut PgConnection,
    revocation: &SessionRevocation,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO iam_revoked_sessions
            (session_id, id, user_id, source, revoked_by, revoked_at, prune_after)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (session_id) DO NOTHING",
    )
    .bind(revocation.session.as_str())
    .bind(revocation.id.as_uuid().as_uuid())
    .bind(revocation.user.as_uuid())
    .bind(revocation.source.as_str())
    .bind(revocation.revoked_by.to_string())
    .bind(timestamp(revocation.revoked_at)?)
    .bind(timestamp(revocation.prune_after)?)
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

async fn upsert_user_cutoff(
    connection: &mut PgConnection,
    cutoff: &UserTokenCutoff,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO iam_user_token_validity
            (user_id, tokens_valid_after, source, updated_at, prune_after)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE SET
            tokens_valid_after = EXCLUDED.tokens_valid_after,
            source = EXCLUDED.source,
            updated_at = EXCLUDED.updated_at,
            prune_after = GREATEST(iam_user_token_validity.prune_after, EXCLUDED.prune_after)
        WHERE EXCLUDED.tokens_valid_after > iam_user_token_validity.tokens_valid_after",
    )
    .bind(cutoff.user.as_uuid())
    .bind(timestamp(cutoff.tokens_valid_after)?)
    .bind(cutoff.source.as_str())
    .bind(timestamp(cutoff.updated_at)?)
    .bind(timestamp(cutoff.prune_after)?)
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

async fn upsert_global_cutoff(
    connection: &mut PgConnection,
    cutoff: &GlobalTokenCutoff,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at)
        VALUES (1, $1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET
            tokens_valid_after = EXCLUDED.tokens_valid_after,
            set_by = EXCLUDED.set_by,
            set_at = EXCLUDED.set_at
        WHERE EXCLUDED.tokens_valid_after > iam_global_token_cutoff.tokens_valid_after",
    )
    .bind(timestamp(cutoff.tokens_valid_after)?)
    .bind(cutoff.set_by.to_string())
    .bind(timestamp(cutoff.set_at)?)
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// The state of the revoked session, or `None` when the session has no record.
///
/// # Errors
///
/// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
pub async fn session_state(
    connection: &mut PgConnection,
    session: &SessionId,
) -> Result<Option<PolicyState>, RepositoryError> {
    let Some(row) = sqlx::query(
        "SELECT user_id, revoked_at, prune_after FROM iam_revoked_sessions WHERE session_id = $1",
    )
    .bind(session.as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(translate)?
    else {
        return Ok(None);
    };
    let user: SqlUuid = row.try_get("user_id").map_err(translate)?;
    let revoked_at: OffsetDateTime = row.try_get("revoked_at").map_err(translate)?;
    let prune_after: OffsetDateTime = row.try_get("prune_after").map_err(translate)?;
    let state = SessionRevocationState {
        session: session.clone(),
        user: Uuid::from_uuid(user),
        revoked_at_micros: micros_of(revoked_at)?,
        prune_after_micros: micros_of(prune_after)?,
    };
    Ok(Some(PolicyState::SessionRevocation(state)))
}

/// The state of the user's cut-off, or `None` when the user has none.
///
/// # Errors
///
/// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
pub async fn user_state(
    connection: &mut PgConnection,
    user: Uuid,
) -> Result<Option<PolicyState>, RepositoryError> {
    let Some(row) = sqlx::query(
        "SELECT tokens_valid_after, prune_after FROM iam_user_token_validity WHERE user_id = $1",
    )
    .bind(user.as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(translate)?
    else {
        return Ok(None);
    };
    let valid_after: OffsetDateTime = row.try_get("tokens_valid_after").map_err(translate)?;
    let prune_after: OffsetDateTime = row.try_get("prune_after").map_err(translate)?;
    let state = UserRevocationState {
        user,
        tokens_valid_after_micros: micros_of(valid_after)?,
        prune_after_micros: micros_of(prune_after)?,
    };
    Ok(Some(PolicyState::UserRevocation(state)))
}

/// The state of the global cut-off, or `None` when none is set.
///
/// # Errors
///
/// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
pub async fn global_state(
    connection: &mut PgConnection,
) -> Result<Option<PolicyState>, RepositoryError> {
    let Some(row) =
        sqlx::query("SELECT tokens_valid_after FROM iam_global_token_cutoff WHERE id = 1")
            .fetch_optional(&mut *connection)
            .await
            .map_err(translate)?
    else {
        return Ok(None);
    };
    let valid_after: OffsetDateTime = row.try_get("tokens_valid_after").map_err(translate)?;
    let state = GlobalRevocationState {
        tokens_valid_after_micros: micros_of(valid_after)?,
    };
    Ok(Some(PolicyState::GlobalRevocation(state)))
}

/// A stored time in whole microseconds since 1970, through the time the stored value stands for.
fn micros_of(value: OffsetDateTime) -> Result<i64, RepositoryError> {
    let time = system_time(value);
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .ok_or_else(|| RepositoryError::Unavailable(Box::new(InvalidIamValue::AuditTimestamp)))
}

#[cfg(test)]
mod tests;
