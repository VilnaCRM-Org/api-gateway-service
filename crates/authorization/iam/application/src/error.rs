//! Application error of the IAM context and its conversion to a problem document.

use axum::http::StatusCode;
use iam_domain::{
    InvalidCatalogueEntry, InvalidEventEnvelope, InvalidIamValue, InvalidRole, InvalidSpec,
    InvalidUserRole, LastAdministratorRefused, RepositoryError, RoleChangeRefused, TokenRejection,
    UserRoleChangeRefused, VersionConflict,
};
use shared_application::http::{Problem, Violation};
use shared_domain::BoxError;

/// The `type` of the 409 problem of an activation that would remove a flag without confirmation.
pub const TYPE_FLAG_DOWNGRADE_CONFIRMATION: &str = "/problems/flag-downgrade-confirmation-required";
/// The `type` of the 409 problem of an activation that would orphan grants without confirmation.
pub const TYPE_ORPHAN_CONFIRMATION: &str = "/problems/orphan-confirmation-required";

/// The `type` of the 409 problem of a change that would leave the platform without an active
/// global administrator.
pub const TYPE_LAST_ADMINISTRATOR: &str = "/problems/last-administrator";

/// What an activation needs the caller to confirm before it changes the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Keys would lose the sensitive or the always-audit flag (`confirmFlagDowngrade`).
    FlagDowngrade,
    /// Grants would become inactive because their key leaves the catalogue (`confirmOrphans`).
    Orphans,
}

impl Confirmation {
    /// The `type` of the problem that asks for the confirmation.
    #[must_use]
    pub const fn problem_type(self) -> &'static str {
        match self {
            Self::FlagDowngrade => TYPE_FLAG_DOWNGRADE_CONFIRMATION,
            Self::Orphans => TYPE_ORPHAN_CONFIRMATION,
        }
    }

    /// The explanation of the problem.
    const fn detail(self) -> &'static str {
        match self {
            Self::FlagDowngrade => {
                "The activation would remove a flag from the listed keys; repeat it with confirmFlagDowngrade to proceed."
            }
            Self::Orphans => {
                "The activation would orphan the listed grants; repeat it with confirmOrphans to proceed."
            }
        }
    }
}

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
    /// The change would revoke the last active global administrator assignment, or give it an
    /// earlier expiry.
    #[error(
        "The last active administrator assignment cannot be revoked or given an earlier expiry."
    )]
    LastAdministrator,
    /// The change needs a confirmation the request did not give; the violations list the keys or
    /// the grants it affects.
    #[error("The change needs a confirmation.")]
    ConfirmationRequired(Confirmation, Vec<Violation>),
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

impl From<InvalidCatalogueEntry> for IamError {
    /// A catalogue statement that names a key of another form or service is a defect of the use
    /// case: the keys come from the version, which belongs to the service of the statement.
    fn from(error: InvalidCatalogueEntry) -> Self {
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

impl From<InvalidUserRole> for IamError {
    /// The violation of an assignment value, with the `property_path` and `code` of the domain.
    fn from(invalid: InvalidUserRole) -> Self {
        Self::Invalid(vec![Violation {
            property_path: invalid.property_path().to_owned(),
            message: invalid.to_string(),
            code: invalid.code().to_owned(),
        }])
    }
}

impl From<LastAdministratorRefused> for IamError {
    fn from(_refusal: LastAdministratorRefused) -> Self {
        Self::LastAdministrator
    }
}

impl From<UserRoleChangeRefused> for IamError {
    /// A revoked assignment is not found, a missing or stale version is a failed precondition, an
    /// expiry that is not in the future is invalid, and a version that cannot grow is a defect.
    fn from(refusal: UserRoleChangeRefused) -> Self {
        match refusal {
            UserRoleChangeRefused::Revoked => Self::NotFound,
            UserRoleChangeRefused::Version(conflict) => Self::from(conflict),
            UserRoleChangeRefused::Range(invalid) => Self::from(invalid),
            UserRoleChangeRefused::Invalid(invalid) => Self::from(invalid),
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
            IamError::LastAdministrator => {
                return Self {
                    r#type: TYPE_LAST_ADMINISTRATOR,
                    ..Self::new(StatusCode::CONFLICT).with_detail(error.to_string())
                };
            }
            IamError::Invalid(violations) => return Self::validation_failed(violations.clone()),
            IamError::ConfirmationRequired(confirmation, items) => {
                return Self {
                    r#type: confirmation.problem_type(),
                    violations: items.clone(),
                    ..Self::new(StatusCode::CONFLICT).with_detail(confirmation.detail())
                };
            }
            IamError::Storage(_) | IamError::Internal(_) => return Self::internal(&error),
        };
        Self::new(status).with_detail(error.to_string())
    }
}

#[cfg(test)]
mod tests;
