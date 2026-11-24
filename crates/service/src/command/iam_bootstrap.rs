//! `service iam-bootstrap`: creates the first IAM administrator (FR-5).
//!
//! The command connects as `serve` does, so it reads the same configuration. It registers IAM's own
//! specifications, creates the system role `iam-platform-admin` and assigns it globally to the
//! subject named by `--admin-user <uuid>` or `--admin-service <service-name>`. With
//! `--iam-host <host>` it also seeds the upstream `iam-control` and the routes of IAM's management
//! API on that host; `--repair-routes --iam-host <host>` restores that seed and creates no
//! administrator.

use std::io::{self, Write};
use std::process::ExitCode;

use iam_application::IamError;
use iam_domain::{RouteHost, SubjectKind, SubjectRef};

use crate::bootstrap::{
    Adapters, AdministratorError, bootstrap_with_routes, repair_gateway_routes,
};
use crate::cli::IamBootstrapArgs;
use crate::command::{self, REJECTED};
use crate::config::Config;

/// Runs `iam-bootstrap`: creates the first administrator or repairs the seeded IAM routes.
///
/// It prints `bootstrapped <subject>`, followed by a line that says whether the IAM routes were
/// seeded; with `--repair-routes` it restores the seeded upstream and routes and prints
/// `repaired the IAM upstream and routes of <host>`.
///
/// Returns 0 on success, 1 when an active administrator assignment exists already or the database
/// or a migration is not ready (the error is printed as `error: <message>`), and 2 for an invalid
/// subject or host option, a `--repair-routes` without `--iam-host` or with a subject option, an
/// invalid configuration, reported as one line per problem, or a seed that finds an upstream
/// `iam-control` or a route of the seeded host that is not a system entry (the message names the
/// entries; `--repair-routes` replaces them).
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
    let plan = match plan_of(&args) {
        Ok(plan) => plan,
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
    match carry_out(&config, plan.clone()) {
        Ok(()) => {
            report(&plan, stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(failure) => Ok(failure_status(&failure, stderr)),
    }
}

/// Reports the failure of the plan and returns its exit status: 2 when the seed finds entries
/// that are not system entries in the place of IAM's own (the message names them and the repair
/// that replaces them), 1 for every other failure.
fn failure_status(failure: &CreateError, stderr: &mut dyn Write) -> ExitCode {
    let conflict = matches!(
        failure,
        CreateError::Administrator(AdministratorError::GatewaySeed(IamError::SeedConflict(_)))
    );
    if !conflict {
        return command::failure(failure, stderr);
    }
    let _written = writeln!(stderr, "error: {failure}").and_then(|()| {
        writeln!(
            stderr,
            "run `service iam-bootstrap --repair-routes --iam-host <host>` to replace them with the system entries"
        )
    });
    ExitCode::from(REJECTED)
}

/// What the command does.
#[derive(Debug, Clone)]
enum Plan {
    /// Creates the first administrator and, with a host, seeds the IAM routes.
    Create {
        subject: SubjectRef,
        iam_host: Option<RouteHost>,
    },
    /// Restores the seeded upstream and routes of the host.
    Repair { iam_host: RouteHost },
}

/// Prints what the successful `plan` did.
fn report(plan: &Plan, stdout: &mut dyn Write) -> io::Result<()> {
    match plan {
        Plan::Create {
            subject,
            iam_host: Some(host),
        } => {
            writeln!(stdout, "bootstrapped {subject}")?;
            writeln!(stdout, "seeded the IAM upstream and routes of {host}")
        }
        Plan::Create {
            subject,
            iam_host: None,
        } => {
            writeln!(stdout, "bootstrapped {subject}")?;
            writeln!(stdout, "no IAM routes seeded: --iam-host is absent")
        }
        Plan::Repair { iam_host } => {
            writeln!(stdout, "repaired the IAM upstream and routes of {iam_host}")
        }
    }
}

/// The plan that the options name.
///
/// # Errors
///
/// The message to print when the subject options are wrong (see [`subject_of`]), the host is no
/// host name, `--repair-routes` lacks `--iam-host` or comes with a subject option.
fn plan_of(args: &IamBootstrapArgs) -> Result<Plan, String> {
    let (user, service) = (args.admin_user.as_deref(), args.admin_service.as_deref());
    if args.repair_routes {
        if user.is_some() || service.is_some() {
            return Err(
                "--repair-routes cannot be used with --admin-user or --admin-service".to_owned(),
            );
        }
        return host_of(args.iam_host.as_deref())?
            .map(|iam_host| Plan::Repair { iam_host })
            .ok_or_else(|| "--repair-routes requires --iam-host".to_owned());
    }
    let subject = subject_of(user, service)?;
    let iam_host = host_of(args.iam_host.as_deref())?;
    Ok(Plan::Create { subject, iam_host })
}

/// The host that `--iam-host` names, when it is given.
///
/// # Errors
///
/// The message to print when the value is no lower-case DNS name.
fn host_of(value: Option<&str>) -> Result<Option<RouteHost>, String> {
    value
        .map(|host| {
            RouteHost::new(host)
                .map_err(|_error| format!("--iam-host: {host:?} is not a lower-case host name"))
        })
        .transpose()
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

/// Runs the plan on a runtime of its own.
fn carry_out(config: &Config, plan: Plan) -> Result<(), CreateError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CreateError::Runtime)?;
    runtime.block_on(async {
        let adapters = Adapters::connect(config)
            .await
            .map_err(CreateError::Wiring)?;
        let outcome = match plan {
            Plan::Create { subject, iam_host } => {
                bootstrap_with_routes(&adapters, subject, iam_host).await
            }
            Plan::Repair { iam_host } => repair_gateway_routes(&adapters, iam_host).await,
        };
        outcome.map_err(CreateError::from)
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
