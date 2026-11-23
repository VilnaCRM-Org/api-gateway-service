//! Why a credential was refused.

use crate::value_object::decision_reason::DecisionReason;

/// The reason a credential does not authenticate its bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TokenRejection {
    /// No credential was presented.
    #[error("no credential was presented")]
    Missing,
    /// The credential is malformed, wrongly signed, from another issuer or audience, or breaks a
    /// claim or lifetime rule.
    #[error("the credential is invalid")]
    Invalid,
    /// The credential's expiry lies further in the past than the allowed clock skew.
    #[error("the credential has expired")]
    Expired,
    /// The session or the subject of the credential was revoked.
    #[error("the credential was revoked")]
    Revoked,
    /// The credential could not be checked because a dependency is unavailable.
    #[error("the credential could not be checked")]
    Unavailable,
}

impl TokenRejection {
    /// The decision reason code of the rejection.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "token_missing",
            Self::Invalid => "token_invalid",
            Self::Expired => "token_expired",
            Self::Revoked => "token_revoked",
            Self::Unavailable => "unavailable",
        }
    }
}

impl From<TokenRejection> for DecisionReason {
    /// The matching `token_*` reason; a credential that cannot be checked is `unavailable`.
    fn from(rejection: TokenRejection) -> Self {
        match rejection {
            TokenRejection::Missing => Self::TokenMissing,
            TokenRejection::Invalid => Self::TokenInvalid,
            TokenRejection::Expired => Self::TokenExpired,
            TokenRejection::Revoked => Self::TokenRevoked,
            TokenRejection::Unavailable => Self::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests;
