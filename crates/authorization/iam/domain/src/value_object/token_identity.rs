//! The identity a memo keeps for a verified token.

use std::time::SystemTime;

use crate::value_object::access_token::AccessToken;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::{SubjectId, SubjectKind};
use crate::value_object::token_id::TokenId;

/// Who a verified token proves the bearer to be and for how long: subject, kind, session, `iat`,
/// `exp` and `jti`. It never holds roles, permissions or grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIdentity {
    subject: SubjectId,
    session: Option<SessionId>,
    token_id: TokenId,
    issued_at: SystemTime,
    expires_at: SystemTime,
}

impl TokenIdentity {
    /// The subject id.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Whether the subject is a user or a service principal.
    #[must_use]
    pub const fn subject_kind(&self) -> SubjectKind {
        self.subject.kind()
    }

    /// The session id, when the token names one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// The token id (`jti`).
    #[must_use]
    pub const fn token_id(&self) -> &TokenId {
        &self.token_id
    }

    /// When the token was issued (`iat`).
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// When the token expires (`exp`).
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

impl From<&AccessToken> for TokenIdentity {
    /// Keeps the identity claims of a verified token and drops its roles.
    fn from(token: &AccessToken) -> Self {
        Self {
            subject: token.subject().clone(),
            session: token.session().cloned(),
            token_id: token.token_id().clone(),
            issued_at: token.issued_at(),
            expires_at: token.expires_at(),
        }
    }
}

#[cfg(test)]
mod tests;
