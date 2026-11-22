//! Application error of the IAM context and its conversion to a problem document.

use axum::http::StatusCode;
use iam_domain::RepositoryError;
use shared_application::http::Problem;
use shared_domain::BoxError;

/// What can go wrong in a command or a query of the IAM context.
#[derive(Debug, thiserror::Error)]
pub enum IamError {
    /// The requested record does not exist.
    #[error("The requested IAM record was not found.")]
    NotFound,
    /// The record already exists or was changed concurrently.
    #[error("The IAM record conflicts with its current state.")]
    Conflict,
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

impl From<IamError> for Problem {
    fn from(error: IamError) -> Self {
        match &error {
            IamError::NotFound => Self::new(StatusCode::NOT_FOUND).with_detail(error.to_string()),
            IamError::Conflict => Self::new(StatusCode::CONFLICT).with_detail(error.to_string()),
            IamError::Storage(_) => Self::internal(&error),
        }
    }
}

#[cfg(test)]
mod tests;
