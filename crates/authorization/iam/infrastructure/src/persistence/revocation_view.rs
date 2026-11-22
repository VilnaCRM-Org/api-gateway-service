//! PostgreSQL implementation of the revocation view port, the reads of `iam-control`.

use iam_domain::{
    RepositoryError, RevocationStatus, RevocationView, SessionId, SubjectId, TokenIdentity,
};

use crate::persistence::revocation::{system_time, unavailable};

/// Reads whether a token's session is revoked, its user's cut-off and the global cut-off from
/// `iam_revoked_sessions`, `iam_user_token_validity` and `iam_global_token_cutoff` in one
/// statement.
#[derive(Debug)]
pub struct PgRevocationView {
    pool: sqlx::PgPool,
}

impl PgRevocationView {
    /// Builds the view over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_status(
        &self,
        identity: &TokenIdentity,
    ) -> Result<RevocationStatus, RepositoryError> {
        let session = identity.session().map(SessionId::as_str);
        let user = user_of(identity.subject());
        let row = sqlx::query!(
            r#"SELECT
                EXISTS (SELECT 1 FROM iam_revoked_sessions WHERE session_id = $1)
                    AS "session_revoked!",
                (SELECT tokens_valid_after FROM iam_user_token_validity WHERE user_id = $2)
                    AS "user_cutoff?",
                (SELECT tokens_valid_after FROM iam_global_token_cutoff WHERE id = 1)
                    AS "global_cutoff?""#,
            session,
            user,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(RevocationStatus {
            session_revoked: row.session_revoked,
            user_cutoff: row.user_cutoff.map(system_time),
            global_cutoff: row.global_cutoff.map(system_time),
        })
    }
}

/// The user id of a user subject; a service principal has no user cut-off.
const fn user_of(subject: &SubjectId) -> Option<sqlx::types::Uuid> {
    match subject {
        SubjectId::User(id) => Some(id.as_uuid()),
        SubjectId::Service(_) => None,
    }
}

#[async_trait::async_trait]
impl RevocationView for PgRevocationView {
    async fn status(&self, identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        self.select_status(identity).await
    }
}

#[cfg(test)]
mod tests;
