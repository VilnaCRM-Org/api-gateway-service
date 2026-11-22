//! The authenticated caller of IAM's own API.

use iam_domain::{SessionId, SubjectId, SubjectKind, TokenId, TokenIdentity};

/// Who called IAM, as its resolved bearer token proves.
///
/// It holds the subject (a user or a service principal), its session and the token id, never the
/// raw token. The composition root puts it into the request extensions and the GraphQL request
/// data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    subject: SubjectId,
    session: Option<SessionId>,
    token_id: TokenId,
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
}

impl From<TokenIdentity> for Principal {
    fn from(identity: TokenIdentity) -> Self {
        Self {
            subject: identity.subject().clone(),
            session: identity.session().cloned(),
            token_id: identity.token_id().clone(),
        }
    }
}

#[cfg(test)]
mod tests;
