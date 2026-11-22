//! Application error of the IAM context and its conversion to a problem document.

use axum::http::StatusCode;
use iam_domain::{RepositoryError, TokenRejection, VersionConflict};
use shared_application::http::Problem;
use shared_domain::BoxError;

/// What can go wrong in a command or a query of the IAM context; `architecture.md` section 5.5
/// maps each variant to its HTTP status and GraphQL code.
#[derive(Debug, thiserror::Error)]
pub enum IamError {
    /// The caller presented no bearer token, or one that is malformed, expired, revoked or not
    /// meant for IAM; the message never says which check failed.
    #[error("A valid bearer token is required.")]
    Unauthenticated,
    /// The requested record does not exist.
    #[error("The requested IAM record was not found.")]
    NotFound,
    /// The record already exists or was changed concurrently.
    #[error("The IAM record conflicts with its current state.")]
    Conflict,
    /// The idempotency key was already used by the same actor for another request in the last 24
    /// hours.
    #[error("The idempotency key was already used for a different request.")]
    IdempotencyMismatch,
    /// An update or a delete names no entity version (`If-Match` or `expectedVersion`).
    #[error("The request must name the version it changes.")]
    PreconditionRequired,
    /// An update or a delete names an entity version that is not the current one.
    #[error("The request names a version that is not the current version.")]
    PreconditionFailed,
    /// The storage failed.
    #[error("the IAM storage is unavailable")]
    Storage(#[source] BoxError),
}

impl From<RepositoryError> for IamError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound => Self::NotFound,
            RepositoryError::AlreadyExists | RepositoryError::Conflict => Self::Conflict,
            unavailable @ RepositoryError::Unavailable(_) => Self::Storage(Box::new(unavailable)),
        }
    }
}

impl From<TokenRejection> for IamError {
    /// Every refusal of the credential is [`IamError::Unauthenticated`]; a revocation state that
    /// cannot be read is a storage failure.
    fn from(rejection: TokenRejection) -> Self {
        match rejection {
            TokenRejection::Unavailable => Self::Storage(Box::new(rejection)),
            TokenRejection::Missing
            | TokenRejection::Invalid
            | TokenRejection::Expired
            | TokenRejection::Revoked => Self::Unauthenticated,
        }
    }
}

impl From<VersionConflict> for IamError {
    fn from(conflict: VersionConflict) -> Self {
        match conflict {
            VersionConflict::Missing => Self::PreconditionRequired,
            VersionConflict::Stale { .. } => Self::PreconditionFailed,
        }
    }
}

impl From<IamError> for Problem {
    fn from(error: IamError) -> Self {
        let status = match &error {
            IamError::Unauthenticated => StatusCode::UNAUTHORIZED,
            IamError::NotFound => StatusCode::NOT_FOUND,
            IamError::Conflict => StatusCode::CONFLICT,
            IamError::IdempotencyMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            IamError::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            IamError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            IamError::Storage(_) => return Self::internal(&error),
        };
        Self::new(status).with_detail(error.to_string())
    }
}

#[cfg(test)]
mod tests;
