//! `service check-config`: validates the configuration of a run mode without opening a socket or
//! contacting a dependency.

use std::io::{self, Write};
use std::process::ExitCode;

use crate::cli::{CheckConfigArgs, Mode};
use crate::command::{self, REJECTED};
use crate::config::{Config, ConfigErrors, GatewayConfig};

/// Prints `configuration OK` and returns 0, or prints one line `<VARIABLE>: <reason>` per problem
/// on standard error and returns 2. A failed write is reported as `error: <message>` with status 1.
///
/// `--mode control` (the default) validates the configuration of `serve`; `--mode gateway` the
/// configuration of `gateway`, which has no database settings.
pub fn run(args: CheckConfigArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match report(args, stdout, stderr) {
        Ok(status) => status,
        Err(error) => command::failure(&error, stderr),
    }
}

fn validate(args: CheckConfigArgs) -> Result<(), ConfigErrors> {
    match args.mode {
        Mode::Control => Config::from_args(args.gateway.service).map(|_config| ()),
        Mode::Gateway => GatewayConfig::from_args(&args.gateway).map(|_config| ()),
    }
}

fn report(
    args: CheckConfigArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<ExitCode> {
    let Err(errors) = validate(args) else {
        writeln!(stdout, "configuration OK")?;
        return Ok(ExitCode::SUCCESS);
    };
    for problem in errors.problems() {
        writeln!(stderr, "{}: {}", problem.variable, problem.reason)?;
    }
    Ok(ExitCode::from(REJECTED))
}
