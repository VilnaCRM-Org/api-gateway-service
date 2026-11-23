use clap::error::ErrorKind;
use clap::{Arg, CommandFactory as _};
use rstest::rstest;

use super::*;

fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("service").chain(arguments.iter().copied()))
}

fn serve_arguments() -> Vec<Arg> {
    ServeArgs::augment_args(clap::Command::new("serve"))
        .get_arguments()
        .cloned()
        .collect()
}

fn subcommand_help(name: &str) -> String {
    let mut command = Cli::command();
    command
        .find_subcommand_mut(name)
        .unwrap()
        .render_long_help()
        .to_string()
}

#[test]
fn serve_takes_every_setting_as_a_flag() {
    let cli = parse(&[
        "serve",
        "--app-env",
        "dev",
        "--app-host",
        "127.0.0.1",
        "--app-port",
        "9000",
        "--log-level",
        "debug",
        "--database-url",
        "postgres://u@h/d",
        "--database-max-connections",
        "7",
        "--database-acquire-timeout",
        "1s",
        "--database-statement-timeout",
        "2s",
        "--aws-region",
        "eu-west-1",
        "--aws-endpoint-url-sqs",
        "http://localhost:4566",
        "--sqs-connect-timeout",
        "300ms",
        "--sqs-operation-timeout",
        "3s",
        "--sqs-max-attempts",
        "2",
        "--health-probe-timeout",
        "4s",
        "--http-request-timeout",
        "5s",
        "--http-max-body-bytes",
        "2048",
        "--shutdown-grace-period",
        "6s",
    ])
    .unwrap();

    let Command::Serve(args) = cli.command else {
        panic!("expected serve");
    };
    assert_eq!(args.app_env.as_deref(), Some("dev"));
    assert_eq!(args.app_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(args.app_port.as_deref(), Some("9000"));
    assert_eq!(args.log_level.as_deref(), Some("debug"));
    assert_eq!(args.database.url.as_deref(), Some("postgres://u@h/d"));
    assert_eq!(args.database.max_connections.as_deref(), Some("7"));
    assert_eq!(args.database.acquire_timeout.as_deref(), Some("1s"));
    assert_eq!(args.database.statement_timeout.as_deref(), Some("2s"));
    assert_eq!(args.aws_region.as_deref(), Some("eu-west-1"));
    assert_eq!(
        args.aws_endpoint_url_sqs.as_deref(),
        Some("http://localhost:4566")
    );
    assert_eq!(args.sqs_connect_timeout.as_deref(), Some("300ms"));
    assert_eq!(args.sqs_operation_timeout.as_deref(), Some("3s"));
    assert_eq!(args.sqs_max_attempts.as_deref(), Some("2"));
    assert_eq!(args.health_probe_timeout.as_deref(), Some("4s"));
    assert_eq!(args.http_request_timeout.as_deref(), Some("5s"));
    assert_eq!(args.http_max_body_bytes.as_deref(), Some("2048"));
    assert_eq!(args.shutdown_grace_period.as_deref(), Some("6s"));
}

#[test]
fn the_credentials_are_accepted_as_hidden_flags() {
    let cli = parse(&[
        "serve",
        "--aws-access-key-id",
        "key",
        "--aws-secret-access-key",
        "secret",
    ])
    .unwrap();

    let Command::Serve(args) = cli.command else {
        panic!("expected serve");
    };
    assert_eq!(args.aws_access_key_id.as_deref(), Some("key"));
    assert_eq!(args.aws_secret_access_key.as_deref(), Some("secret"));
}

#[test]
fn serve_takes_the_token_settings_as_flags() {
    let cli = parse(&[
        "serve",
        "--jwt-public-keys-file",
        "keys.pem",
        "--jwt-issuer",
        "issuer",
        "--jwt-audience",
        "audience",
        "--jwt-clock-skew",
        "10s",
        "--max-token-lifetime",
        "5m",
        "--token-memo-capacity",
        "5000",
        "--token-memo-max-ttl",
        "1m",
        "--jwt-caller-audience",
        "callers",
        "--jwt-service-token-max-lifetime",
        "2m",
    ])
    .unwrap();

    let Command::Serve(args) = cli.command else {
        panic!("expected serve");
    };
    assert_eq!(args.tokens.public_keys_file.as_deref(), Some("keys.pem"));
    assert_eq!(args.tokens.issuer.as_deref(), Some("issuer"));
    assert_eq!(args.tokens.audience.as_deref(), Some("audience"));
    assert_eq!(args.tokens.clock_skew.as_deref(), Some("10s"));
    assert_eq!(args.tokens.max_token_lifetime.as_deref(), Some("5m"));
    assert_eq!(args.tokens.memo_capacity.as_deref(), Some("5000"));
    assert_eq!(args.tokens.memo_max_ttl.as_deref(), Some("1m"));
    assert_eq!(args.tokens.caller_audience.as_deref(), Some("callers"));
    assert_eq!(
        args.tokens.service_token_max_lifetime.as_deref(),
        Some("2m")
    );
}

#[test]
fn check_config_takes_the_arguments_of_serve() {
    let cli = parse(&["check-config", "--app-port", "9000"]).unwrap();

    let Command::CheckConfig(args) = cli.command else {
        panic!("expected check-config");
    };
    assert_eq!(args.gateway.service.app_port.as_deref(), Some("9000"));
    assert_eq!(args.mode, Mode::Control);
}

#[test]
fn check_config_and_healthcheck_take_a_run_mode() {
    let check = parse(&["check-config", "--mode", "gateway"]).unwrap();
    let probe = parse(&["healthcheck", "--mode", "gateway"]).unwrap();
    let default = parse(&["healthcheck"]).unwrap();

    let (Command::CheckConfig(check), Command::Healthcheck(probe), Command::Healthcheck(default)) =
        (check.command, probe.command, default.command)
    else {
        panic!("expected check-config and healthcheck");
    };
    assert_eq!(check.mode, Mode::Gateway);
    assert_eq!(probe.mode, Mode::Gateway);
    assert_eq!(default.mode, Mode::Control);
}

#[test]
fn an_unknown_run_mode_is_a_usage_error() {
    let error = parse(&["check-config", "--mode", "worker"]).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidValue);
}

#[test]
fn gateway_takes_every_gateway_setting_as_a_flag() {
    let cli = parse(&[
        "gateway",
        "--gateway-listen",
        "0.0.0.0:1",
        "--gateway-internal-listen",
        "0.0.0.0:2",
        "--gateway-probe-listen",
        "0.0.0.0:3",
        "--gateway-tls-cert-file",
        "cert.pem",
        "--gateway-tls-key-file",
        "key.pem",
        "--pod-name",
        "gateway-0",
        "--pod-namespace",
        "iam",
        "--app-env",
        "dev",
    ])
    .unwrap();

    let Command::Gateway(args) = cli.command else {
        panic!("expected gateway");
    };
    assert_eq!(args.listen.as_deref(), Some("0.0.0.0:1"));
    assert_eq!(args.internal_listen.as_deref(), Some("0.0.0.0:2"));
    assert_eq!(args.probe_listen.as_deref(), Some("0.0.0.0:3"));
    assert_eq!(args.tls_cert_file.as_deref(), Some("cert.pem"));
    assert_eq!(args.tls_key_file.as_deref(), Some("key.pem"));
    assert_eq!(args.pod_name.as_deref(), Some("gateway-0"));
    assert_eq!(args.pod_namespace.as_deref(), Some("iam"));
    assert_eq!(args.service.app_env.as_deref(), Some("dev"));
}

#[test]
fn the_gateway_settings_are_bound_to_their_variables_and_hide_their_values() {
    let command = Cli::command();
    let gateway = command.find_subcommand("gateway").unwrap();

    for (id, variable) in [
        ("listen", "GATEWAY_LISTEN"),
        ("internal_listen", "GATEWAY_INTERNAL_LISTEN"),
        ("probe_listen", "GATEWAY_PROBE_LISTEN"),
        ("tls_cert_file", "GATEWAY_TLS_CERT_FILE"),
        ("tls_key_file", "GATEWAY_TLS_KEY_FILE"),
        ("pod_name", "POD_NAME"),
        ("pod_namespace", "POD_NAMESPACE"),
    ] {
        let argument = gateway
            .get_arguments()
            .find(|argument| argument.get_id() == id)
            .unwrap();
        assert_eq!(argument.get_env().unwrap(), variable);
        assert!(argument.is_hide_env_values_set());
    }
}

#[test]
fn migrate_applies_by_default_and_reverts_on_request() {
    let apply = parse(&["migrate", "--wait-timeout", "5s", "--database-url", "u"]).unwrap();
    let revert = parse(&["migrate", "revert"]).unwrap();

    let Command::Migrate(apply) = apply.command else {
        panic!("expected migrate");
    };
    assert_eq!(apply.action, None);
    assert_eq!(apply.wait_timeout.as_deref(), Some("5s"));
    assert_eq!(apply.database.url.as_deref(), Some("u"));
    let Command::Migrate(revert) = revert.command else {
        panic!("expected migrate");
    };
    assert_eq!(revert.action, Some(MigrateAction::Revert));
}

#[rstest]
#[case("openapi-export")]
#[case("graphql-export")]
fn the_exports_take_an_optional_output_path(#[case] name: &str) {
    let to_stdout = parse(&[name]).unwrap();
    let to_file = parse(&[name, "--output", "out.txt"]).unwrap();

    let (Command::OpenapiExport(stdout) | Command::GraphqlExport(stdout)) = to_stdout.command
    else {
        panic!("expected an export");
    };
    let (Command::OpenapiExport(file) | Command::GraphqlExport(file)) = to_file.command else {
        panic!("expected an export");
    };
    assert_eq!(stdout.output, None);
    assert_eq!(file.output, Some(PathBuf::from("out.txt")));
}

#[test]
fn the_export_commands_are_told_apart() {
    assert!(matches!(
        parse(&["openapi-export"]).unwrap().command,
        Command::OpenapiExport(_)
    ));
    assert!(matches!(
        parse(&["graphql-export"]).unwrap().command,
        Command::GraphqlExport(_)
    ));
}

#[test]
fn healthcheck_takes_a_port_and_a_host() {
    let cli = parse(&["healthcheck", "--port", "9100", "--host", "10.0.3.7"]).unwrap();

    let Command::Healthcheck(args) = cli.command else {
        panic!("expected healthcheck");
    };
    assert_eq!(args.port.as_deref(), Some("9100"));
    assert_eq!(args.host.as_deref(), Some("10.0.3.7"));
}

#[rstest]
#[case(&["frobnicate"], ErrorKind::InvalidSubcommand)]
#[case(&["serve", "--frobnicate"], ErrorKind::UnknownArgument)]
#[case(&["--frobnicate"], ErrorKind::UnknownArgument)]
#[case(&[], ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand)]
fn a_usage_error_has_exit_status_2(#[case] arguments: &[&str], #[case] kind: ErrorKind) {
    let error = parse(arguments).unwrap_err();

    assert_eq!(error.kind(), kind);
    assert_eq!(error.exit_code(), 2);
}

#[rstest]
#[case("--help")]
#[case("--version")]
fn help_and_version_are_not_failures(#[case] flag: &str) {
    let error = parse(&[flag]).unwrap_err();

    assert_eq!(error.exit_code(), 0);
    assert!(!error.use_stderr());
}

#[test]
fn the_version_is_the_package_version() {
    let error = parse(&["--version"]).unwrap_err();

    assert_eq!(
        error.to_string().trim(),
        format!("service {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn every_setting_is_bound_to_a_variable_whose_value_is_never_printed() {
    let arguments = serve_arguments();

    assert!(
        arguments
            .iter()
            .all(|argument| argument.get_env().is_some())
    );
    assert!(arguments.iter().all(Arg::is_hide_env_values_set));
}

#[test]
fn serve_declares_exactly_the_variables_of_the_configuration_table() {
    let mut variables: Vec<String> = serve_arguments()
        .iter()
        .filter_map(|argument| argument.get_env())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    variables.sort();

    let mut expected = vec![
        "APP_ENV",
        "APP_HOST",
        "APP_PORT",
        "AWS_ACCESS_KEY_ID",
        "AWS_ENDPOINT_URL_SQS",
        "AWS_REGION",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_ACQUIRE_TIMEOUT",
        "DATABASE_MAX_CONNECTIONS",
        "DATABASE_STATEMENT_TIMEOUT",
        "DATABASE_URL",
        "HEALTH_PROBE_TIMEOUT",
        "HTTP_MAX_BODY_BYTES",
        "HTTP_REQUEST_TIMEOUT",
        "JWT_AUDIENCE",
        "JWT_CALLER_AUDIENCE",
        "JWT_CLOCK_SKEW",
        "JWT_ISSUER",
        "JWT_PUBLIC_KEYS_FILE",
        "JWT_SERVICE_TOKEN_MAX_LIFETIME",
        "EVENTS_TOPIC",
        "KAFKA_BOOTSTRAP_SERVERS",
        "KAFKA_CA_FILE",
        "KAFKA_CLIENT_ID",
        "KAFKA_CONFIG_GATES",
        "KAFKA_CONNECT_TIMEOUT",
        "KAFKA_REQUEST_TIMEOUT",
        "KAFKA_RETRY_DELAY",
        "KAFKA_SASL_MECHANISM",
        "KAFKA_SASL_PASSWORD",
        "KAFKA_SASL_USERNAME",
        "KAFKA_SECURITY_PROTOCOL",
        "POLICY_TOPIC",
        "LOG_LEVEL",
        "MAX_TOKEN_LIFETIME",
        "SHUTDOWN_GRACE_PERIOD",
        "SQS_CONNECT_TIMEOUT",
        "SQS_MAX_ATTEMPTS",
        "SQS_OPERATION_TIMEOUT",
        "TOKEN_MEMO_CAPACITY",
        "TOKEN_MEMO_MAX_TTL",
    ];
    expected.sort_unstable();
    assert_eq!(variables, expected);
}

#[test]
fn only_the_two_credentials_are_hidden_from_the_help() {
    let mut hidden: Vec<String> = serve_arguments()
        .iter()
        .filter(|argument| argument.is_hide_set())
        .map(|argument| argument.get_id().to_string())
        .collect();
    hidden.sort();

    assert_eq!(hidden, ["aws_access_key_id", "aws_secret_access_key"]);
}

#[test]
fn the_serve_help_lists_every_variable_but_the_credentials() {
    let help = subcommand_help("serve");

    for argument in serve_arguments().iter().filter(|a| !a.is_hide_set()) {
        let flag = format!("--{}", argument.get_long().unwrap());
        assert!(help.contains(&flag), "{flag} is missing");
        let variable = argument.get_env().unwrap().to_string_lossy();
        assert!(help.contains(&format!("[env: {variable}]")));
    }
    assert!(!help.contains("AWS_ACCESS_KEY_ID"));
    assert!(!help.contains("AWS_SECRET_ACCESS_KEY"));
}

#[test]
fn the_migrate_and_healthcheck_settings_are_bound_to_their_variables() {
    let migrate = Cli::command();
    let migrate = migrate.find_subcommand("migrate").unwrap();
    let healthcheck = Cli::command();
    let healthcheck = healthcheck.find_subcommand("healthcheck").unwrap();

    let wait = migrate
        .get_arguments()
        .find(|argument| argument.get_id() == "wait_timeout")
        .unwrap();
    let port = healthcheck
        .get_arguments()
        .find(|argument| argument.get_id() == "port")
        .unwrap();
    assert_eq!(wait.get_env().unwrap(), "DATABASE_WAIT_TIMEOUT");
    assert!(wait.is_hide_env_values_set());
    let host = healthcheck
        .get_arguments()
        .find(|argument| argument.get_id() == "host")
        .unwrap();
    assert_eq!(port.get_env().unwrap(), "APP_PORT");
    assert!(port.is_hide_env_values_set());
    assert_eq!(host.get_env().unwrap(), "APP_HOST");
    assert!(host.is_hide_env_values_set());
}

#[test]
fn iam_bootstrap_takes_the_service_settings_and_one_subject_option() {
    let user = parse(&[
        "iam-bootstrap",
        "--admin-user",
        "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
        "--database-url",
        "postgres://u@h/d",
    ])
    .unwrap();
    let service = parse(&["iam-bootstrap", "--admin-service", "schemathesis"]).unwrap();

    let Command::IamBootstrap(user) = user.command else {
        panic!("expected iam-bootstrap");
    };
    let Command::IamBootstrap(service) = service.command else {
        panic!("expected iam-bootstrap");
    };
    assert_eq!(
        user.admin_user.as_deref(),
        Some("0190f2a8-7b3c-7d4e-8f10-1234567890ab")
    );
    assert_eq!(user.admin_service, None);
    assert_eq!(
        user.service.database.url.as_deref(),
        Some("postgres://u@h/d")
    );
    assert_eq!(service.admin_service.as_deref(), Some("schemathesis"));
    assert_eq!(service.admin_user, None);
}

#[test]
fn iam_bootstrap_accepts_neither_or_both_options_because_the_command_reports_them() {
    assert!(parse(&["iam-bootstrap"]).is_ok());
    assert!(parse(&["iam-bootstrap", "--admin-user", "x", "--admin-service", "y"]).is_ok());
}
