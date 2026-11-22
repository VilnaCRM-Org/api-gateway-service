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

/// A verified access token: who the bearer is, for which audiences and for how long, never what
/// it may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    parts: AccessTokenParts,
    audiences: Vec<String>,
}

impl AccessToken {
    /// Wraps claims that the verifier has already checked; the token names no audience until
    /// [`Self::with_audiences`] adds them.
    #[must_use]
    pub const fn new(parts: AccessTokenParts) -> Self {
        Self {
            parts,
            audiences: Vec::new(),
        }
    }

    /// The same token with the audiences of its `aud` claim.
    #[must_use]
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    /// The audiences of the `aud` claim.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// The subject id.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.parts.subject
    }

    /// Whether the subject is a user or a service principal.
    #[must_use]
    pub const fn subject_kind(&self) -> SubjectKind {
        self.parts.subject.kind()
    }

    /// The session id, when the token names one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.parts.session.as_ref()
    }

    /// The token id.
    #[must_use]
    pub const fn token_id(&self) -> &TokenId {
        &self.parts.token_id
    }

    /// The roles claim.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.parts.roles
    }

    /// When the token was issued.
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime {
        self.parts.issued_at
    }

    /// When the token expires.
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.parts.expires_at
    }
}

#[cfg(test)]
mod tests;
