//! `service iam-bootstrap`: creates the first IAM administrator (FR-5).
//!
//! The command connects as `serve` does, so it reads the same configuration. It registers IAM's own
//! specifications, creates the system role `iam-platform-admin` and assigns it globally to the
//! subject named by `--admin-user <uuid>` or `--admin-service <service-name>`.

use std::io::{self, Write};
use std::process::ExitCode;

use iam_domain::{SubjectKind, SubjectRef};

use crate::bootstrap::{Adapters, AdministratorError, bootstrap_administrator};
use crate::cli::IamBootstrapArgs;
use crate::command::{self, REJECTED};
use crate::config::Config;

/// Creates the first administrator and prints `bootstrapped <subject>`.
///
/// Returns 0 on success, 1 when an active administrator assignment exists already or the database
/// or a migration is not ready (the error is printed as `error: <message>`), and 2 for an invalid
/// subject option or invalid configuration, reported as one line per problem.
pub fn run(args: IamBootstrapArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match execute(args, stdout, stderr) {
        Ok(status) => status,
        Err(error) => command::failure(&error, stderr),
    }
}

fn execute(
    args: IamBootstrapArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<ExitCode> {
    let subject = match subject_of(args.admin_user.as_deref(), args.admin_service.as_deref()) {
        Ok(subject) => subject,
        Err(message) => {
            writeln!(stderr, "{message}")?;
            return Ok(ExitCode::from(REJECTED));
        }
    };
    let config = match Config::from_args(args.service) {
        Ok(config) => config,
        Err(errors) => {
            for problem in errors.problems() {
                writeln!(stderr, "{}: {}", problem.variable, problem.reason)?;
            }
            return Ok(ExitCode::from(REJECTED));
        }
    };
    match create(&config, subject.clone()) {
        Ok(()) => {
            writeln!(stdout, "bootstrapped {subject}")?;
            Ok(ExitCode::SUCCESS)
        }
        Err(failure) => Ok(command::failure(&failure, stderr)),
    }
}

/// Why the administrator could not be created.
#[derive(Debug, thiserror::Error)]
enum CreateError {
    #[error("the runtime could not start: {0}")]
    Runtime(#[source] io::Error),
    #[error("the service could not be wired: {0}")]
    Wiring(#[source] crate::bootstrap::BootstrapError),
    #[error("{0}")]
    Administrator(#[from] AdministratorError),
}

/// Runs the creation on a runtime of its own.
fn create(config: &Config, subject: SubjectRef) -> Result<(), CreateError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CreateError::Runtime)?;
    runtime.block_on(async {
        let adapters = Adapters::connect(config)
            .await
            .map_err(CreateError::Wiring)?;
        bootstrap_administrator(&adapters, subject)
            .await
            .map_err(CreateError::from)
    })
}

/// The subject that exactly one of the two options names.
///
/// # Errors
///
/// The message to print when neither or both are given, or the value is no UUID (`--admin-user`)
/// or no service name (`--admin-service`).
fn subject_of(user: Option<&str>, service: Option<&str>) -> Result<SubjectRef, String> {
    match (user, service) {
        (Some(id), None) => SubjectRef::new(SubjectKind::User, id)
            .map_err(|_error| format!("--admin-user: {id:?} is not a UUID")),
        (None, Some(name)) => SubjectRef::new(SubjectKind::Service, name)
            .map_err(|_error| format!("--admin-service: {name:?} is not a service name")),
        (None, None) => Err("one of --admin-user and --admin-service is required".to_owned()),
        (Some(_), Some(_)) => {
            Err("--admin-user and --admin-service cannot be used together".to_owned())
        }
    }
}

#[cfg(test)]
mod tests;
