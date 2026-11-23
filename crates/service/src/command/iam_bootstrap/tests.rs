use std::io::{self, Write};

use iam_domain::SubjectKind;

use super::{run, subject_of};
use crate::cli::IamBootstrapArgs;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn run_with(args: IamBootstrapArgs) -> (std::process::ExitCode, String, String) {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let status = run(args, &mut stdout, &mut stderr);
    (
        status,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn a_user_is_named_by_a_uuid_and_a_service_by_its_name() {
    let user = subject_of(Some(USER), None).unwrap();
    let service = subject_of(None, Some("schemathesis")).unwrap();

    assert_eq!(user.kind(), SubjectKind::User);
    assert_eq!(user.to_string(), format!("user:{USER}"));
    assert_eq!(service.kind(), SubjectKind::Service);
    assert_eq!(service.to_string(), "service:schemathesis");
}

#[test]
fn neither_both_or_an_invalid_value_is_a_message() {
    assert_eq!(
        subject_of(None, None).unwrap_err(),
        "one of --admin-user and --admin-service is required"
    );
    assert_eq!(
        subject_of(Some(USER), Some("schemathesis")).unwrap_err(),
        "--admin-user and --admin-service cannot be used together"
    );
    assert!(
        subject_of(Some("nope"), None)
            .unwrap_err()
            .starts_with("--admin-user: ")
    );
    assert!(
        subject_of(None, Some("Not A Service"))
            .unwrap_err()
            .starts_with("--admin-service: ")
    );
}

#[test]
fn a_rejected_subject_exits_with_2_and_a_message_before_any_connection() {
    let (status, stdout, stderr) = run_with(IamBootstrapArgs::default());

    assert_eq!(status, std::process::ExitCode::from(2));
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "one of --admin-user and --admin-service is required\n"
    );
}

#[test]
fn invalid_configuration_exits_with_2_and_names_every_variable() {
    let args = IamBootstrapArgs {
        admin_user: Some(USER.to_owned()),
        ..IamBootstrapArgs::default()
    };

    let (status, stdout, stderr) = run_with(args);

    assert_eq!(status, std::process::ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("DATABASE_URL: "), "{stderr}");
}

/// A writer that fails every write.
#[derive(Debug)]
struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_that_cannot_be_written_exits_with_1() {
    let mut stdout = Vec::new();

    let status = run(IamBootstrapArgs::default(), &mut stdout, &mut BrokenWriter);

    assert_eq!(status, std::process::ExitCode::from(1));
    assert_eq!(stdout, b"");
}
