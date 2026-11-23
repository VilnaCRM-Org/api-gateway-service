//! Application error of the IAM context and its conversion to a problem document.

use axum::http::StatusCode;
use iam_domain::{
    InvalidEventEnvelope, InvalidIamValue, InvalidRole, InvalidSpec, RepositoryError,
    RoleChangeRefused, TokenRejection, VersionConflict,
};
use shared_application::http::{Problem, Violation};
use shared_domain::BoxError;

/// What can go wrong in a command or a query of the IAM context; `architecture.md` section 5.5
/// maps each variant to its HTTP status and GraphQL code.
#[derive(Debug, thiserror::Error)]
pub enum IamError {
    /// The caller presented no bearer token, or one that is malformed, expired, revoked or not
    /// meant for IAM; the message never says which check failed.
    #[error("A valid bearer token is required.")]
    Unauthenticated,
    /// The caller may not change the record, such as a system role.
    #[error("The IAM record cannot be changed through the API.")]
    Forbidden,
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
    /// The request holds values that break the rules of the record; each violation names its
    /// property.
    #[error("The request holds invalid values.")]
    Invalid(Vec<Violation>),
    /// The storage failed.
    #[error("the IAM storage is unavailable")]
    Storage(#[source] BoxError),
    /// A value that the use case itself produced breaks an invariant of the domain; a defect, never
    /// a mistake of the client.
    #[error("the IAM use case produced an invalid value")]
    Internal(#[source] BoxError),
}

impl From<Vec<InvalidRole>> for IamError {
    /// Every violation of a role, as the `property_path` and `code` of the domain give them.
    fn from(violations: Vec<InvalidRole>) -> Self {
        Self::Invalid(
            violations
                .into_iter()
                .map(|violation| Violation {
                    property_path: violation.property_path().to_owned(),
                    message: violation.to_string(),
                    code: violation.code().to_owned(),
                })
                .collect(),
        )
    }
}

impl IamError {
    /// A violation of one property of the request.
    pub(crate) fn invalid_property(property_path: &str, message: &str, code: &str) -> Self {
        Self::Invalid(vec![Violation {
            property_path: property_path.to_owned(),
            message: message.to_owned(),
            code: code.to_owned(),
        }])
    }
}

impl From<InvalidSpec> for IamError {
    /// The violation of a specification document that cannot become a version, with the position
    /// of the fault in its message.
    fn from(error: InvalidSpec) -> Self {
        Self::Invalid(vec![Violation {
            property_path: error.property_path().to_owned(),
            message: error.to_string(),
            code: error.code().to_owned(),
        }])
    }
}

impl From<InvalidIamValue> for IamError {
    fn from(error: InvalidIamValue) -> Self {
        Self::Internal(Box::new(error))
    }
}

impl From<InvalidEventEnvelope> for IamError {
    fn from(error: InvalidEventEnvelope) -> Self {
        Self::Internal(Box::new(error))
    }
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

impl From<RoleChangeRefused> for IamError {
    /// A system role is forbidden, a deleted role is not found, a missing or stale version is a
    /// failed precondition, and a version that cannot grow is a defect.
    fn from(refusal: RoleChangeRefused) -> Self {
        match refusal {
            RoleChangeRefused::SystemRole => Self::Forbidden,
            RoleChangeRefused::Deleted => Self::NotFound,
            RoleChangeRefused::Version(conflict) => Self::from(conflict),
            RoleChangeRefused::Invalid(invalid) => Self::from(invalid),
        }
    }
}

impl From<IamError> for Problem {
    fn from(error: IamError) -> Self {
        let status = match &error {
            IamError::Unauthenticated => StatusCode::UNAUTHORIZED,
            IamError::Forbidden => StatusCode::FORBIDDEN,
            IamError::NotFound => StatusCode::NOT_FOUND,
            IamError::Conflict => StatusCode::CONFLICT,
            IamError::IdempotencyMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            IamError::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            IamError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            IamError::Invalid(violations) => return Self::validation_failed(violations.clone()),
            IamError::Storage(_) | IamError::Internal(_) => return Self::internal(&error),
        };
        Self::new(status).with_detail(error.to_string())
    }
}

#[cfg(test)]
mod tests;
