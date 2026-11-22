//! The identity a verified User service token proves.

use std::time::SystemTime;

use crate::value_object::session_id::SessionId;
use crate::value_object::subject::{SubjectId, SubjectKind};
use crate::value_object::token_id::TokenId;

/// The validated claims an [`AccessToken`] is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenParts {
    /// The subject: a user id for a `ROLE_USER` token, a service name for a `ROLE_SERVICE` token.
    pub subject: SubjectId,
    /// The User service session (`sid`); present whenever the token carries roles.
    pub session: Option<SessionId>,
    /// The token id (`jti`).
    pub token_id: TokenId,
    /// The roles claim as issued.
    pub roles: Vec<String>,
    /// When the token was issued (`iat`).
    pub issued_at: SystemTime,
    /// When the token expires (`exp`).
    pub expires_at: SystemTime,
}

/// A verified access token: who the bearer is and for how long, never what it may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken(AccessTokenParts);

impl AccessToken {
    /// Wraps claims that the verifier has already checked.
    #[must_use]
    pub const fn new(parts: AccessTokenParts) -> Self {
        Self(parts)
    }

    /// The subject id.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.0.subject
    }

    /// Whether the subject is a user or a service principal.
    #[must_use]
    pub const fn subject_kind(&self) -> SubjectKind {
        self.0.subject.kind()
    }

    /// The session id, when the token names one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.0.session.as_ref()
    }

    /// The token id.
    #[must_use]
    pub const fn token_id(&self) -> &TokenId {
        &self.0.token_id
    }

    /// The roles claim.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.0.roles
    }

    /// When the token was issued.
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime {
        self.0.issued_at
    }

    /// When the token expires.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.0.expires_at
    }
}

#[cfg(test)]
mod tests;
