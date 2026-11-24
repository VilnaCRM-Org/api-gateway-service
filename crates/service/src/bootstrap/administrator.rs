//! The bootstrap of the first IAM administrator: the work of `service iam-bootstrap` (FR-5).

use std::sync::Arc;

use iam_application::{
    BootstrapIamCommand, BootstrapIamCommandHandler, IamError, SeedIamGatewayCommand,
    SeedIamGatewayCommandHandler, SeedMode,
};
use iam_domain::{
    BOOTSTRAP_LOCK, ChangeId, RepositoryError, RoleId, RouteHost, SubjectRef, UserRoleId,
};
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
    /// The upstream `iam-control` or the routes of IAM's management API could not be written.
    #[error("the IAM upstream and routes could not be written: {0}")]
    GatewaySeed(#[source] IamError),
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
    bootstrap_with_routes(adapters, subject, None).await
}

/// Creates the first administrator and, when `iam_host` is given, seeds the IAM routes.
///
/// The administrator is created as [`bootstrap_administrator`] does; the upstream `iam-control`
/// and the routes of IAM's management API on that host are seeded under the same lock, as
/// `system:bootstrap`; an entry that exists is left as it is.
///
/// The seed follows the administrator, so a run that finds an administrator refuses before it
/// writes anything. A run that fails while it seeds leaves the administrator in place; the repair
/// of [`repair_gateway_routes`] completes the seed.
///
/// # Errors
///
/// The errors of [`bootstrap_administrator`] and [`AdministratorError::GatewaySeed`] when the
/// seed cannot be written.
pub async fn bootstrap_with_routes(
    adapters: &Adapters,
    subject: SubjectRef,
    iam_host: Option<RouteHost>,
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
    handler.handle(command).await.map_err(refusal_of)?;
    match iam_host {
        Some(host) => seed_gateway(adapters, host, SeedMode::Seed).await,
        None => Ok(()),
    }
}

/// Restores the upstream `iam-control` and the IAM routes on `iam_host` to their seeded state.
///
/// The repair runs whether or not an administrator exists, under the bootstrap lock: an absent
/// entry is inserted and a changed one is updated, as a revocation-class change audited as
/// `system:bootstrap`.
///
/// # Errors
///
/// [`AdministratorError::Lock`] when the lock cannot be taken and
/// [`AdministratorError::GatewaySeed`] when an entry cannot be written.
pub async fn repair_gateway_routes(
    adapters: &Adapters,
    iam_host: RouteHost,
) -> Result<(), AdministratorError> {
    let _lock = adapters
        .startup_lock
        .acquire(BOOTSTRAP_LOCK)
        .await
        .map_err(AdministratorError::Lock)?;
    seed_gateway(adapters, iam_host, SeedMode::Repair).await
}

/// Seeds or repairs the upstream and the routes on `host`.
async fn seed_gateway(
    adapters: &Adapters,
    host: RouteHost,
    mode: SeedMode,
) -> Result<(), AdministratorError> {
    let handler = SeedIamGatewayCommandHandler::new(
        Arc::clone(&adapters.upstreams),
        Arc::clone(&adapters.routes),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    handler
        .handle(SeedIamGatewayCommand { host, mode })
        .await
        .map_err(AdministratorError::GatewaySeed)
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
