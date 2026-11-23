//! The bootstrap of the first IAM administrator: the work of `service iam-bootstrap` (FR-5).

use std::sync::Arc;

use iam_application::{BootstrapIamCommand, BootstrapIamCommandHandler, IamError};
use iam_domain::{BOOTSTRAP_LOCK, ChangeId, RepositoryError, RoleId, SubjectRef, UserRoleId};
use shared_domain::CommandHandler as _;

use super::{Adapters, BootstrapError, register_iam_specs};

/// Why the administrator could not be bootstrapped.
#[derive(Debug, thiserror::Error)]
pub enum AdministratorError {
    /// The bootstrap lock could not be taken.
    #[error("the bootstrap lock could not be taken: {0}")]
    Lock(#[source] RepositoryError),
    /// IAM's own specifications could not be registered.
    #[error("IAM's own specifications could not be registered: {0}")]
    Registration(#[source] BootstrapError),
    /// An active administrator assignment exists already.
    #[error("an active assignment of iam-platform-admin exists already")]
    AlreadyBootstrapped,
    /// The role or its assignment could not be created.
    #[error("the administrator could not be created: {0}")]
    Creation(#[source] IamError),
}

/// Creates the first administrator.
///
/// It takes a transaction-level advisory lock, registers IAM's
/// own specifications through [`register_iam_specs`], then creates the system role
/// `iam-platform-admin` with its keys and assigns it globally to `subject`, as
/// `system:bootstrap`. Of two runs that start together, the second finds the assignment of the
/// first and fails with [`AdministratorError::AlreadyBootstrapped`] without a change.
///
/// # Errors
///
/// [`AdministratorError::Lock`] when the lock cannot be taken,
/// [`AdministratorError::Registration`] when the specifications cannot be registered,
/// [`AdministratorError::AlreadyBootstrapped`] when an active global assignment of the role exists
/// and [`AdministratorError::Creation`] for any other failure of the change.
pub async fn bootstrap_administrator(
    adapters: &Adapters,
    subject: SubjectRef,
) -> Result<(), AdministratorError> {
    let _lock = adapters
        .startup_lock
        .acquire(BOOTSTRAP_LOCK)
        .await
        .map_err(AdministratorError::Lock)?;
    register_iam_specs(adapters)
        .await
        .map_err(AdministratorError::Registration)?;
    let handler = BootstrapIamCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.user_roles),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let command = BootstrapIamCommand {
        change_id: ChangeId::from_uuid(adapters.uuid_generator.generate()),
        role_id: RoleId::from_uuid(adapters.uuid_generator.generate()),
        user_role_id: UserRoleId::from_uuid(adapters.uuid_generator.generate()),
        subject,
    };
    handler.handle(command).await.map_err(refusal_of)
}

/// The error of a bootstrap whose change failed: a conflict means the administrator exists.
fn refusal_of(error: IamError) -> AdministratorError {
    if matches!(error, IamError::Conflict) {
        AdministratorError::AlreadyBootstrapped
    } else {
        AdministratorError::Creation(error)
    }
}

#[cfg(test)]
mod tests;
