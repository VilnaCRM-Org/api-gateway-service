use std::io::{self, Write};

use iam_application::IamError;
use iam_domain::SubjectKind;

use super::{CreateError, Plan, failure_status, host_of, plan_of, report, run, subject_of};
use crate::bootstrap::AdministratorError;
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

fn args(user: Option<&str>, host: Option<&str>, repair: bool) -> IamBootstrapArgs {
    IamBootstrapArgs {
        admin_user: user.map(str::to_owned),
        iam_host: host.map(str::to_owned),
        repair_routes: repair,
        ..IamBootstrapArgs::default()
    }
}

#[test]
fn a_host_is_a_lower_case_dns_name_and_optional() {
    assert_eq!(
        host_of(Some("iam.example.test"))
            .unwrap()
            .unwrap()
            .to_string(),
        "iam.example.test"
    );
    assert!(host_of(None).unwrap().is_none());
    assert_eq!(
        host_of(Some("Not A Host")).unwrap_err(),
        "--iam-host: \"Not A Host\" is not a lower-case host name"
    );
}

#[test]
fn a_subject_with_or_without_a_host_is_a_create_plan() {
    let with_host = plan_of(&args(Some(USER), Some("iam.example.test"), false)).unwrap();
    let without_host = plan_of(&args(Some(USER), None, false)).unwrap();

    assert!(matches!(
        with_host,
        Plan::Create {
            iam_host: Some(_),
            ..
        }
    ));
    assert!(matches!(without_host, Plan::Create { iam_host: None, .. }));
}

#[test]
fn an_invalid_host_is_a_message_even_with_a_valid_subject() {
    let message = plan_of(&args(Some(USER), Some("Nope!"), false)).unwrap_err();

    assert!(message.starts_with("--iam-host: "), "{message}");
}

#[test]
fn the_subject_is_checked_before_the_host() {
    let message = plan_of(&args(None, Some("Nope!"), false)).unwrap_err();

    assert_eq!(
        message,
        "one of --admin-user and --admin-service is required"
    );
}

#[test]
fn repair_needs_a_host_and_takes_no_subject() {
    let plan = plan_of(&args(None, Some("iam.example.test"), true)).unwrap();

    assert!(matches!(plan, Plan::Repair { .. }));
    assert_eq!(
        plan_of(&args(None, None, true)).unwrap_err(),
        "--repair-routes requires --iam-host"
    );
    assert_eq!(
        plan_of(&args(Some(USER), Some("iam.example.test"), true)).unwrap_err(),
        "--repair-routes cannot be used with --admin-user or --admin-service"
    );
    assert!(
        plan_of(&args(None, Some("Nope!"), true))
            .unwrap_err()
            .starts_with("--iam-host: ")
    );
}

#[test]
fn repair_without_a_host_exits_with_2_before_any_connection() {
    let (status, stdout, stderr) = run_with(args(None, None, true));

    assert_eq!(status, std::process::ExitCode::from(2));
    assert_eq!(stdout, "");
    assert_eq!(stderr, "--repair-routes requires --iam-host\n");
}

#[test]
fn an_invalid_host_exits_with_2_before_any_connection() {
    let (status, stdout, stderr) = run_with(args(Some(USER), Some("Nope!"), false));

    assert_eq!(status, std::process::ExitCode::from(2));
    assert_eq!(stdout, "");
    assert!(stderr.starts_with("--iam-host: "), "{stderr}");
}

#[test]
fn the_report_says_whether_the_routes_were_seeded_or_repaired() {
    let subject = subject_of(Some(USER), None).unwrap();
    let host = host_of(Some("iam.example.test")).unwrap().unwrap();
    let render = |plan: &Plan| {
        let mut stdout = Vec::new();
        report(plan, &mut stdout).unwrap();
        String::from_utf8(stdout).unwrap()
    };

    assert_eq!(
        render(&Plan::Create {
            subject: subject.clone(),
            iam_host: Some(host.clone()),
        }),
        format!(
            "bootstrapped user:{USER}\nseeded the IAM upstream and routes of iam.example.test\n"
        )
    );
    assert_eq!(
        render(&Plan::Create {
            subject,
            iam_host: None,
        }),
        format!("bootstrapped user:{USER}\nno IAM routes seeded: --iam-host is absent\n")
    );
    assert_eq!(
        render(&Plan::Repair { iam_host: host }),
        "repaired the IAM upstream and routes of iam.example.test\n"
    );
}

#[test]
fn a_seed_conflict_exits_with_2_and_names_the_entries_and_the_repair() {
    let mut stderr = Vec::new();
    let failure = CreateError::Administrator(AdministratorError::GatewaySeed(
        IamError::SeedConflict("upstream iam-control (u1)".to_owned()),
    ));

    let status = failure_status(&failure, &mut stderr);

    assert_eq!(status, std::process::ExitCode::from(2));
    let text = String::from_utf8(stderr).unwrap();
    assert!(text.starts_with("error: "), "{text}");
    assert!(text.contains("upstream iam-control (u1)"), "{text}");
    assert!(text.contains("--repair-routes"), "{text}");
}

#[test]
fn any_other_seed_failure_exits_with_1() {
    let mut stderr = Vec::new();
    let failure = CreateError::Administrator(AdministratorError::GatewaySeed(IamError::Conflict));

    let status = failure_status(&failure, &mut stderr);

    assert_eq!(status, std::process::ExitCode::from(1));
    assert!(String::from_utf8(stderr).unwrap().starts_with("error: "));
}
