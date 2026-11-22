//! Wire shapes of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::TokenRejection;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::principal::Principal;
use crate::query::resolve_subject_token::TokenResolution;

/// Body of the token-resolution operation.
///
/// Its `Debug` output never shows the credential.
#[derive(Clone, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = TokenResolutionRequest)]
pub struct TokenResolutionRequest {
    /// The User service token to resolve; an empty one resolves as `token_missing`.
    #[schema(max_length = 8192, example = "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl")]
    #[validate(length(
        max = 8192,
        message = "This value must contain at most 8192 characters."
    ))]
    pub credential: String,
}

impl std::fmt::Debug for TokenResolutionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResolutionRequest")
            .finish_non_exhaustive()
    }
}

/// The answer of the token-resolution operation.
///
/// A resolved credential carries the subject, the session, the roles claim and the expiry; a
/// refused one carries the reason code. The credential itself is never echoed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TokenResolution)]
pub struct TokenResolutionResponse {
    /// Whether the credential is valid and unrevoked.
    pub resolved: bool,
    /// Why the credential is refused: `token_missing`, `token_invalid`, `token_expired` or
    /// `token_revoked`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "token_expired")]
    pub reason: Option<String>,
    /// The user id, or the service name of a service principal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// `user` or `service`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "user")]
    pub subject_kind: Option<String>,
    /// The User service session of the token, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The roles claim of the token as issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// When the token expires, in seconds since 1970-01-01T00:00:00Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 0)]
    pub expires_at: Option<i64>,
}

impl TokenResolutionResponse {
    /// The answer for a refused credential.
    #[must_use]
    pub fn unresolved(rejection: TokenRejection) -> Self {
        Self {
            resolved: false,
            reason: Some(rejection.code().to_owned()),
            subject_id: None,
            subject_kind: None,
            session_id: None,
            roles: None,
            expires_at: None,
        }
    }

    /// The answer for the principal of a valid credential.
    #[must_use]
    pub fn resolved(principal: &Principal) -> Self {
        Self {
            resolved: true,
            reason: None,
            subject_id: Some(principal.subject().to_string()),
            subject_kind: Some(principal.subject_kind().as_str().to_owned()),
            session_id: principal
                .session()
                .map(|session| session.as_str().to_owned()),
            roles: Some(principal.roles().to_vec()),
            expires_at: Some(epoch_seconds(principal.expires_at())),
        }
    }
}

impl From<TokenResolution> for TokenResolutionResponse {
    fn from(resolution: TokenResolution) -> Self {
        match resolution {
            TokenResolution::Resolved(principal) => Self::resolved(&principal),
            TokenResolution::Unresolved(rejection) => Self::unresolved(rejection),
        }
    }
}

/// Whole seconds since 1970; zero before 1970 and the largest `i64` when the time does not fit.
fn epoch_seconds(time: std::time::SystemTime) -> i64 {
    let elapsed = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
