//! The authenticated caller of IAM's own API.

use std::time::SystemTime;

use iam_domain::{SessionId, SubjectId, SubjectKind, TokenId, TokenIdentity};

/// Who called IAM, as its resolved bearer token proves.
///
/// It holds the subject (a user or a service principal), its session, the token id, the roles
/// claim and the expiry, never the raw token; its `Debug` output names no role. The composition
/// root puts it into the request extensions and the GraphQL request data.
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    subject: SubjectId,
    session: Option<SessionId>,
    token_id: TokenId,
    roles: Vec<String>,
    expires_at: SystemTime,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("subject", &self.subject)
            .field("session", &self.session)
            .field("token_id", &self.token_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Principal {
    /// The subject id.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Whether the caller is a user or a service principal.
    #[must_use]
    pub const fn subject_kind(&self) -> SubjectKind {
        self.subject.kind()
    }

    /// The session of the token, when it names one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// The token id (`jti`).
    #[must_use]
    pub const fn token_id(&self) -> &TokenId {
        &self.token_id
    }

    /// The roles claim of the token as issued.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// When the token expires (`exp`).
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

impl From<TokenIdentity> for Principal {
    fn from(identity: TokenIdentity) -> Self {
        Self {
            subject: identity.subject().clone(),
            session: identity.session().cloned(),
            token_id: identity.token_id().clone(),
            roles: identity.roles().to_vec(),
            expires_at: identity.expires_at(),
        }
    }
}

#[cfg(test)]
mod tests;
