use std::fs::File;
use std::process::Stdio;

use rstest::rstest;

use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;

use crate::support::{Scratch, VALID_ENVIRONMENT, stderr, stdout};

const FULL_ENVIRONMENT: [(&str, &str); 41] = [
    ("APP_ENV", "dev"),
    ("APP_HOST", "127.0.0.1"),
    ("APP_PORT", "0"),
    ("LOG_LEVEL", "debug"),
    (
        "DATABASE_URL",
        "postgres://app:local-dev-only@127.0.0.1:5432/app",
    ),
    ("DATABASE_MAX_CONNECTIONS", "5"),
    ("DATABASE_ACQUIRE_TIMEOUT", "1s"),
    ("DATABASE_STATEMENT_TIMEOUT", "2s"),
    ("AWS_REGION", "us-east-1"),
    ("AWS_ENDPOINT_URL_SQS", "http://127.0.0.1:1"),
    ("AWS_ACCESS_KEY_ID", "test"),
    ("AWS_SECRET_ACCESS_KEY", "test"),
    ("SQS_CONNECT_TIMEOUT", "300ms"),
    ("SQS_OPERATION_TIMEOUT", "1s"),
    ("SQS_MAX_ATTEMPTS", "2"),
    ("HEALTH_PROBE_TIMEOUT", "2s"),
    ("HTTP_REQUEST_TIMEOUT", "5s"),
    ("HTTP_MAX_BODY_BYTES", "2048"),
    ("SHUTDOWN_GRACE_PERIOD", "3s"),
    ("JWT_PUBLIC_KEYS_FILE", DEVELOPMENT_PUBLIC_KEYS_FILE),
    ("JWT_ISSUER", "vilnacrm-user-service"),
    ("JWT_AUDIENCE", "vilnacrm-api"),
    ("JWT_CLOCK_SKEW", "60s"),
    ("MAX_TOKEN_LIFETIME", "15m"),
    ("TOKEN_MEMO_CAPACITY", "200000"),
    ("TOKEN_MEMO_MAX_TTL", "900s"),
    ("JWT_CALLER_AUDIENCE", "vilnacrm-iam"),
    ("JWT_SERVICE_TOKEN_MAX_LIFETIME", "600s"),
    ("KAFKA_BOOTSTRAP_SERVERS", "kafka-1:9094,kafka-2:9094"),
    ("KAFKA_SECURITY_PROTOCOL", "SASL_SSL"),
    ("KAFKA_SASL_MECHANISM", "SCRAM-SHA-256"),
    ("KAFKA_SASL_USERNAME", "iam-control"),
    ("KAFKA_SASL_PASSWORD", "not-a-real-password"),
    ("KAFKA_CA_FILE", "/etc/kafka/ca.pem"),
    ("KAFKA_CLIENT_ID", "iam-control-1"),
    ("KAFKA_CONNECT_TIMEOUT", "500ms"),
    ("KAFKA_REQUEST_TIMEOUT", "1s"),
    ("KAFKA_RETRY_DELAY", "50ms"),
    ("KAFKA_CONFIG_GATES", "enforce"),
    ("POLICY_TOPIC", "iam.policy.state.v1"),
    ("EVENTS_TOPIC", "iam.events.v1"),
];

#[test]
fn a_valid_environment_exits_0_and_prints_configuration_ok() {
    let scratch = Scratch::new();

    let output = scratch.run(&["check-config"], &VALID_ENVIRONMENT);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
    assert_eq!(stderr(&output), "");
}

#[test]
fn every_variable_of_the_table_is_accepted_together() {
    let scratch = Scratch::new();

    let output = scratch.run(&["check-config"], &FULL_ENVIRONMENT);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn flags_replace_variables() {
    let scratch = Scratch::new();

    let output = scratch.run(
        &[
            "check-config",
            "--database-url",
            "postgres://u@h/d",
            "--aws-region",
            "eu-west-1",
        ],
        &[],
    );

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn every_invalid_or_missing_variable_is_named_in_one_run_without_its_value() {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["check-config"],
        &[
            ("DATABASE_URL", "mysql://user:hunter2@h/db"),
            ("APP_PORT", "99999"),
            ("APP_ENV", "staging"),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    let errors = stderr(&output);
    let lines: Vec<&str> = errors.lines().collect();
    assert_eq!(lines.len(), 4, "{errors}");
    assert!(lines[0].starts_with("APP_ENV: "));
    assert!(lines[1].starts_with("APP_PORT: "));
    assert!(lines[2].starts_with("DATABASE_URL: "));
    assert!(lines[3].starts_with("AWS_REGION: "));
    assert!(!errors.contains("hunter2"));
    assert!(!errors.contains("99999"));
    assert!(!errors.contains("staging"));
}

#[test]
fn an_sqs_endpoint_with_a_malformed_host_is_named_without_its_value() {
    let scratch = Scratch::new();
    let variables = [
        VALID_ENVIRONMENT[0],
        VALID_ENVIRONMENT[1],
        ("AWS_ENDPOINT_URL_SQS", "http://exa mple:4566"),
    ];

    let output = scratch.run(&["check-config"], &variables);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    let errors = stderr(&output);
    assert_eq!(
        errors,
        "AWS_ENDPOINT_URL_SQS: must be an http:// or https:// URL\n"
    );
    assert!(!errors.contains("exa mple"));
}

#[rstest]
#[case("0")]
#[case("500us")]
#[case("30d")]
fn a_statement_timeout_outside_its_range_is_rejected(#[case] value: &str) {
    let scratch = Scratch::new();
    let variables = [
        VALID_ENVIRONMENT[0],
        VALID_ENVIRONMENT[1],
        ("DATABASE_STATEMENT_TIMEOUT", value),
    ];

    let output = scratch.run(&["check-config"], &variables);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "DATABASE_STATEMENT_TIMEOUT: must be a duration from 1ms to 24d\n"
    );
}

#[test]
fn a_key_id_without_a_secret_names_the_missing_variable() {
    let scratch = Scratch::new();
    let variables = [
        VALID_ENVIRONMENT[0],
        VALID_ENVIRONMENT[1],
        ("AWS_ACCESS_KEY_ID", "key"),
    ];

    let output = scratch.run(&["check-config"], &variables);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output),
        "AWS_SECRET_ACCESS_KEY: is required when AWS_ACCESS_KEY_ID is set\n"
    );
}

#[test]
fn a_secret_without_a_key_id_names_the_missing_variable() {
    let scratch = Scratch::new();
    let variables = [
        VALID_ENVIRONMENT[0],
        VALID_ENVIRONMENT[1],
        ("AWS_SECRET_ACCESS_KEY", "secret"),
    ];

    let output = scratch.run(&["check-config"], &variables);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output),
        "AWS_ACCESS_KEY_ID: is required when AWS_SECRET_ACCESS_KEY is set\n"
    );
}

#[test]
fn both_credentials_set_or_both_unset_is_valid() {
    let scratch = Scratch::new();
    let both = [
        VALID_ENVIRONMENT[0],
        VALID_ENVIRONMENT[1],
        ("AWS_ACCESS_KEY_ID", "key"),
        ("AWS_SECRET_ACCESS_KEY", "secret"),
    ];

    assert_eq!(scratch.run(&["check-config"], &both).status.code(), Some(0));
    assert_eq!(
        scratch
            .run(&["check-config"], &VALID_ENVIRONMENT)
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn the_help_lists_every_flag_and_never_a_value() {
    let scratch = Scratch::new();
    let variables = [
        ("DATABASE_URL", "postgres://u:topsecret@h/db"),
        ("AWS_SECRET_ACCESS_KEY", "credentialvalue"),
        ("APP_PORT", "4242"),
    ];

    let serve = scratch.run(&["serve", "--help"], &variables);
    let root = scratch.run(&["--help"], &variables);

    for output in [&serve, &root] {
        assert_eq!(output.status.code(), Some(0));
        let text = stdout(output);
        assert!(!text.contains("topsecret"));
        assert!(!text.contains("credentialvalue"));
        assert!(!text.contains("4242"));
    }
    let help = stdout(&serve);
    for flag in [
        "--app-env",
        "--app-host",
        "--app-port",
        "--log-level",
        "--database-url",
        "--database-max-connections",
        "--database-acquire-timeout",
        "--database-statement-timeout",
        "--aws-region",
        "--aws-endpoint-url-sqs",
        "--sqs-connect-timeout",
        "--sqs-operation-timeout",
        "--sqs-max-attempts",
        "--health-probe-timeout",
        "--http-request-timeout",
        "--http-max-body-bytes",
        "--shutdown-grace-period",
        "--jwt-public-keys-file",
        "--jwt-issuer",
        "--jwt-audience",
        "--jwt-clock-skew",
        "--max-token-lifetime",
    ] {
        assert!(help.contains(flag), "{flag} is missing from the help");
    }
    assert!(help.contains("[env: DATABASE_URL]"));
    assert!(!help.contains("AWS_ACCESS_KEY_ID"));
    assert!(!help.contains("AWS_SECRET_ACCESS_KEY"));
    assert!(stdout(&root).contains("check-config"));
}

#[test]
fn the_version_is_the_package_version() {
    let scratch = Scratch::new();

    let output = scratch.run(&["--version"], &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        format!("service {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[rstest]
#[case(&["frobnicate"])]
#[case(&["worker"])]
#[case(&["check-config", "--frobnicate"])]
#[case(&[])]
fn a_usage_error_exits_2_with_the_text_on_stderr(#[case] arguments: &[&str]) {
    let scratch = Scratch::new();

    let output = scratch.run(arguments, &VALID_ENVIRONMENT);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("Usage:"));
}

#[test]
fn the_env_file_of_the_working_directory_is_loaded() {
    let scratch = Scratch::new();
    scratch.write(
        ".env",
        "DB_USER=u\nDATABASE_URL=postgres://${DB_USER}:p@h/d\nAWS_REGION=us-east-1\n",
    );

    let output = scratch.run(&["check-config"], &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn the_process_environment_wins_over_the_env_file() {
    let scratch = Scratch::new();
    scratch.write(".env", "APP_PORT=9000\n");

    let invalid_in_the_process = scratch.run(
        &["check-config"],
        &[
            VALID_ENVIRONMENT[0],
            VALID_ENVIRONMENT[1],
            ("APP_PORT", "not-a-port"),
        ],
    );
    scratch.write(".env", "APP_PORT=not-a-port\n");
    let valid_in_the_process = scratch.run(
        &["check-config"],
        &[
            VALID_ENVIRONMENT[0],
            VALID_ENVIRONMENT[1],
            ("APP_PORT", "9001"),
        ],
    );

    assert_eq!(invalid_in_the_process.status.code(), Some(2));
    assert!(stderr(&invalid_in_the_process).starts_with("APP_PORT: "));
    assert_eq!(valid_in_the_process.status.code(), Some(0));
}

#[test]
fn a_directory_without_an_env_file_has_no_configuration() {
    let scratch = Scratch::new();
    assert!(!scratch.path().join(".env").exists());

    let output = scratch.run(&["check-config"], &[]);

    assert_eq!(output.status.code(), Some(2));
    let errors = stderr(&output);
    assert!(errors.starts_with("DATABASE_URL: is required\n"));
    assert!(errors.contains("AWS_REGION: is required\n"));
}

#[test]
fn a_failed_write_of_the_success_line_exits_1() {
    let scratch = Scratch::new();
    let mut command = scratch.service(&["check-config"], &VALID_ENVIRONMENT);
    command.stdout(Stdio::from(
        File::options().write(true).open("/dev/full").unwrap(),
    ));

    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: "));
}

#[test]
fn a_failed_write_of_a_problem_line_exits_1() {
    let scratch = Scratch::new();
    let mut command = scratch.service(&["check-config"], &[]);
    command.stderr(Stdio::from(
        File::options().write(true).open("/dev/full").unwrap(),
    ));

    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
}

#[test]
fn a_failed_write_of_the_help_exits_1() {
    let scratch = Scratch::new();
    let mut command = scratch.service(&["--help"], &[]);
    command.stdout(Stdio::from(
        File::options().write(true).open("/dev/full").unwrap(),
    ));

    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(1));
}

/// Runs `check-config` with a valid environment plus `extra`.
fn check_config_with(scratch: &Scratch, extra: &[(&str, &str)]) -> std::process::Output {
    let mut variables = VALID_ENVIRONMENT.to_vec();
    variables.extend_from_slice(extra);
    scratch.run(&["check-config"], &variables)
}

#[test]
fn a_clock_skew_above_sixty_seconds_exits_2_naming_the_variable() {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, &[("JWT_CLOCK_SKEW", "61s")]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "JWT_CLOCK_SKEW: must be a duration of at most 60s\n"
    );
}

#[test]
fn a_token_memo_capacity_below_1000_exits_2_naming_the_variable() {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, &[("TOKEN_MEMO_CAPACITY", "999")]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "TOKEN_MEMO_CAPACITY: must be an integer of at least 1000\n"
    );
}

#[test]
fn a_token_memo_ttl_above_max_token_lifetime_exits_2_naming_the_variable() {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("MAX_TOKEN_LIFETIME", "900s"),
            ("TOKEN_MEMO_MAX_TTL", "901s"),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "TOKEN_MEMO_MAX_TTL: must be a duration of at most MAX_TOKEN_LIFETIME\n"
    );
}

#[test]
fn token_memo_settings_within_their_bounds_are_accepted() {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("TOKEN_MEMO_CAPACITY", "1000"),
            ("MAX_TOKEN_LIFETIME", "900s"),
            ("TOKEN_MEMO_MAX_TTL", "900s"),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[rstest]
#[case::above_one_hour("2h", "3601s")]
#[case::above_max_token_lifetime("900s", "901s")]
fn a_service_token_lifetime_out_of_bounds_exits_2_naming_the_variable(
    #[case] max_token_lifetime: &str,
    #[case] service_lifetime: &str,
) {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("MAX_TOKEN_LIFETIME", max_token_lifetime),
            ("JWT_SERVICE_TOKEN_MAX_LIFETIME", service_lifetime),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "JWT_SERVICE_TOKEN_MAX_LIFETIME: must be a duration of at least 1s, at most 3600s and at \
         most MAX_TOKEN_LIFETIME\n"
    );
}

#[test]
fn a_service_token_lifetime_of_one_hour_is_accepted() {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("MAX_TOKEN_LIFETIME", "1h"),
            ("JWT_SERVICE_TOKEN_MAX_LIFETIME", "3600s"),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn a_missing_key_file_variable_exits_2_naming_it() {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, &[("JWT_PUBLIC_KEYS_FILE", "")]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), "JWT_PUBLIC_KEYS_FILE: must not be empty\n");
}

fn development_key() -> String {
    std::fs::read_to_string(DEVELOPMENT_PUBLIC_KEYS_FILE).unwrap()
}

#[rstest]
#[case::no_key(String::new(), "the key file holds no PEM key")]
#[case::four_keys(
    development_key().repeat(4),
    "the key file holds 4 keys, but at most 3 are allowed"
)]
#[case::unparsable(
    "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n".to_owned(),
    "key 1 of the key file is not a parsable RSA public key in PEM form"
)]
fn a_key_file_the_service_cannot_use_exits_2_naming_the_variable(
    #[case] contents: String,
    #[case] cause: &str,
) {
    let scratch = Scratch::new();
    scratch.write("keys.pem", &contents);
    let path = scratch.path().join("keys.pem");

    let output = check_config_with(
        &scratch,
        &[("JWT_PUBLIC_KEYS_FILE", path.to_str().unwrap())],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    let errors = stderr(&output);
    assert_eq!(
        errors,
        format!("JWT_PUBLIC_KEYS_FILE: must name a file of 1 to 3 PEM RSA public keys: {cause}\n")
    );
    assert!(!errors.contains(path.to_str().unwrap()));
}

#[test]
fn a_key_file_of_three_keys_is_accepted() {
    let scratch = Scratch::new();
    scratch.write("keys.pem", &development_key().repeat(3));
    let path = scratch.path().join("keys.pem");

    let output = check_config_with(
        &scratch,
        &[("JWT_PUBLIC_KEYS_FILE", path.to_str().unwrap())],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[rstest]
#[case::relaxed_gates_in_prod(
    &[("APP_ENV", "prod"), ("KAFKA_CONFIG_GATES", "relaxed")],
    "KAFKA_CONFIG_GATES: must be enforce unless APP_ENV is dev or test\n"
)]
#[case::relaxed_gates_without_an_environment(
    &[("KAFKA_CONFIG_GATES", "relaxed")],
    "KAFKA_CONFIG_GATES: must be enforce unless APP_ENV is dev or test\n"
)]
#[case::plaintext_in_prod(
    &[("APP_ENV", "prod"), ("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")],
    "KAFKA_SECURITY_PROTOCOL: must be SASL_SSL unless APP_ENV is dev or test\n"
)]
#[case::plaintext_without_an_environment(
    &[("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")],
    "KAFKA_SECURITY_PROTOCOL: must be SASL_SSL unless APP_ENV is dev or test\n"
)]
#[case::both_in_prod(
    &[
        ("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        ("KAFKA_CONFIG_GATES", "relaxed"),
    ],
    "KAFKA_SECURITY_PROTOCOL: must be SASL_SSL unless APP_ENV is dev or test\n\
     KAFKA_CONFIG_GATES: must be enforce unless APP_ENV is dev or test\n"
)]
#[case::an_unknown_protocol(
    &[("KAFKA_SECURITY_PROTOCOL", "SSL")],
    "KAFKA_SECURITY_PROTOCOL: must be one of SASL_SSL, PLAINTEXT\n"
)]
#[case::an_unknown_gate(
    &[("KAFKA_CONFIG_GATES", "lenient")],
    "KAFKA_CONFIG_GATES: must be one of enforce, relaxed\n"
)]
#[case::an_unknown_mechanism(
    &[("KAFKA_SASL_MECHANISM", "PLAIN")],
    "KAFKA_SASL_MECHANISM: must be one of SCRAM-SHA-512, SCRAM-SHA-256\n"
)]
#[case::a_bootstrap_address_without_a_port(
    &[("KAFKA_BOOTSTRAP_SERVERS", "kafka-1")],
    "KAFKA_BOOTSTRAP_SERVERS: must be comma-separated host:port pairs\n"
)]
#[case::a_bootstrap_list_with_an_empty_entry(
    &[("KAFKA_BOOTSTRAP_SERVERS", "kafka-1:9094,")],
    "KAFKA_BOOTSTRAP_SERVERS: must be comma-separated host:port pairs\n"
)]
#[case::an_empty_ca_file(
    &[("KAFKA_CA_FILE", " ")],
    "KAFKA_CA_FILE: must not be empty\n"
)]
#[case::a_request_timeout_below_the_connect_timeout(
    &[("KAFKA_CONNECT_TIMEOUT", "3s"), ("KAFKA_REQUEST_TIMEOUT", "2s")],
    "KAFKA_REQUEST_TIMEOUT: must not be shorter than KAFKA_CONNECT_TIMEOUT\n"
)]
#[case::a_malformed_retry_delay(
    &[("KAFKA_RETRY_DELAY", "soon")],
    "KAFKA_RETRY_DELAY: must be a duration such as 500ms, 2s or 1m\n"
)]
#[case::a_publish_wait_timeout_above_the_limit(
    &[("PUBLISH_WAIT_TIMEOUT", "31s")],
    "PUBLISH_WAIT_TIMEOUT: must be a duration from 100ms to 30s\n"
)]
#[case::a_malformed_publish_wait_timeout(
    &[("PUBLISH_WAIT_TIMEOUT", "soon")],
    "PUBLISH_WAIT_TIMEOUT: must be a duration such as 500ms, 2s or 1m\n"
)]
#[case::the_same_topic_twice(
    &[("POLICY_TOPIC", "iam.shared"), ("EVENTS_TOPIC", "iam.shared")],
    "EVENTS_TOPIC: must differ from POLICY_TOPIC\n"
)]
#[case::a_topic_name_with_a_space(
    &[("POLICY_TOPIC", "iam policy")],
    "POLICY_TOPIC: must be a Kafka topic name of at most 249 letters, digits, '.', '_' and '-'\n"
)]
fn an_invalid_kafka_setting_exits_2_naming_the_variable(
    #[case] extra: &[(&str, &str)],
    #[case] problems: &str,
) {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, extra);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), problems);
}

#[rstest]
#[case::dev("dev")]
#[case::test("test")]
fn plaintext_and_relaxed_gates_are_accepted_in_dev_and_test(#[case] environment: &str) {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("APP_ENV", environment),
            ("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
            ("KAFKA_CONFIG_GATES", "relaxed"),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn a_missing_bootstrap_server_exits_2_naming_the_variable() {
    let scratch = Scratch::new();
    let mut command = scratch.service(&["check-config"], &VALID_ENVIRONMENT);
    command.env_remove("KAFKA_BOOTSTRAP_SERVERS");

    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), "KAFKA_BOOTSTRAP_SERVERS: is required\n");
}

#[test]
fn sasl_credentials_are_required_with_sasl_ssl_and_ignored_with_plaintext() {
    let scratch = Scratch::new();
    let mut secured = scratch.service(&["check-config"], &VALID_ENVIRONMENT);
    secured.env_remove("KAFKA_SASL_USERNAME");
    secured.env_remove("KAFKA_SASL_PASSWORD");
    let mut plaintext = scratch.service(
        &["check-config"],
        &[
            VALID_ENVIRONMENT[0],
            VALID_ENVIRONMENT[1],
            ("APP_ENV", "dev"),
            ("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        ],
    );
    plaintext.env_remove("KAFKA_SASL_USERNAME");
    plaintext.env_remove("KAFKA_SASL_PASSWORD");

    let refused = secured.output().unwrap();
    let accepted = plaintext.output().unwrap();

    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        stderr(&refused),
        "KAFKA_SASL_USERNAME: is required\nKAFKA_SASL_PASSWORD: is required\n"
    );
    assert_eq!(accepted.status.code(), Some(0));
}

#[test]
fn the_sasl_password_is_never_printed() {
    let scratch = Scratch::new();

    let invalid = check_config_with(
        &scratch,
        &[
            ("KAFKA_SASL_PASSWORD", "hunter2-kafka"),
            ("KAFKA_SASL_MECHANISM", "PLAIN"),
        ],
    );
    let help = scratch.run(
        &["serve", "--help"],
        &[("KAFKA_SASL_PASSWORD", "hunter2-kafka")],
    );

    assert_eq!(invalid.status.code(), Some(2));
    assert!(!stderr(&invalid).contains("hunter2-kafka"));
    assert!(stdout(&help).contains("[env: KAFKA_SASL_PASSWORD]"));
    assert!(!stdout(&help).contains("hunter2-kafka"));
}

const GATEWAY_ENVIRONMENT: [(&str, &str); 1] = [("APP_ENV", "test")];

#[test]
fn the_gateway_mode_needs_no_database_setting() {
    let scratch = Scratch::new();

    let output = scratch.run(&["check-config", "--mode", "gateway"], &GATEWAY_ENVIRONMENT);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
    assert_eq!(stderr(&output), "");
}

#[test]
fn the_same_configuration_in_control_mode_names_the_database() {
    let scratch = Scratch::new();

    let default = scratch.run(&["check-config"], &GATEWAY_ENVIRONMENT);
    let control = scratch.run(&["check-config", "--mode", "control"], &GATEWAY_ENVIRONMENT);

    for output in [default, control] {
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(stdout(&output), "");
        assert!(
            stderr(&output).contains("DATABASE_URL: is required"),
            "{}",
            stderr(&output)
        );
    }
}

#[rstest]
#[case::below_the_range(("FRESHNESS_HARD_BOUND", "2s"), "FRESHNESS_HARD_BOUND: must be a duration from 3s to 30s\n")]
#[case::above_the_range(("FRESHNESS_HARD_BOUND", "31s"), "FRESHNESS_HARD_BOUND: must be a duration from 3s to 30s\n")]
#[case::not_above_the_ready_bound(
    ("FRESHNESS_READY_BOUND", "15s"),
    "FRESHNESS_HARD_BOUND: must be longer than FRESHNESS_READY_BOUND\n"
)]
#[case::zero_fetch_wait(
    ("KAFKA_FETCH_MAX_WAIT", "0s"),
    "KAFKA_FETCH_MAX_WAIT: must be a positive duration such as 10m or 90d\n"
)]
#[case::zero_probe_interval(
    ("FRESHNESS_PROBE_INTERVAL", "0s"),
    "FRESHNESS_PROBE_INTERVAL: must be a positive duration such as 10m or 90d\n"
)]
#[case::zero_derived_state_check_interval(
    ("DERIVED_STATE_CHECK_INTERVAL", "0s"),
    "DERIVED_STATE_CHECK_INTERVAL: must be a positive duration such as 10m or 90d\n"
)]
fn a_freshness_or_fetch_setting_out_of_range_exits_2_naming_the_variable(
    #[case] setting: (&str, &str),
    #[case] expected: &str,
) {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["check-config", "--mode", "gateway"],
        &[GATEWAY_ENVIRONMENT[0], setting],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), expected);
}

#[rstest]
#[case::internal_equals_public(
    ("GATEWAY_INTERNAL_LISTEN", "127.0.0.1:9100"),
    "GATEWAY_INTERNAL_LISTEN: must differ from GATEWAY_LISTEN\n"
)]
#[case::probe_equals_public(
    ("GATEWAY_PROBE_LISTEN", "127.0.0.1:9100"),
    "GATEWAY_PROBE_LISTEN: must differ from GATEWAY_LISTEN\n"
)]
fn equal_listener_addresses_exit_2_naming_the_variable(
    #[case] other: (&str, &str),
    #[case] expected: &str,
) {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["check-config", "--mode", "gateway"],
        &[
            GATEWAY_ENVIRONMENT[0],
            ("GATEWAY_LISTEN", "127.0.0.1:9100"),
            other,
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), expected);
}

#[test]
fn missing_tls_files_outside_dev_and_test_exit_2_naming_both_variables() {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["check-config", "--mode", "gateway"],
        &[("APP_ENV", "prod")],
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output),
        "GATEWAY_TLS_CERT_FILE: is required outside APP_ENV dev and test\nGATEWAY_TLS_KEY_FILE: is required outside APP_ENV dev and test\n"
    );
}

#[rstest]
#[case::username("KAFKA_BOOTSTRAP_SASL_USERNAME")]
#[case::password("KAFKA_BOOTSTRAP_SASL_PASSWORD")]
fn a_missing_bootstrap_credential_outside_dev_and_test_exits_2_naming_the_variable(
    #[case] variable: &str,
) {
    let scratch = Scratch::new();
    let pair = test_support::tls::self_signed(scratch.path(), "gateway", "bootstrap");
    let mut command = scratch.service(
        &["check-config", "--mode", "gateway"],
        &[
            ("APP_ENV", "prod"),
            ("GATEWAY_TLS_CERT_FILE", pair.cert.to_str().unwrap()),
            ("GATEWAY_TLS_KEY_FILE", pair.key.to_str().unwrap()),
        ],
    );
    command.env_remove(variable);

    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), format!("{variable}: is required\n"));
}

#[test]
fn a_usable_tls_pair_is_accepted_in_prod() {
    let scratch = Scratch::new();
    let pair = test_support::tls::self_signed(scratch.path(), "gateway", "check");

    let output = scratch.run(
        &["check-config", "--mode", "gateway"],
        &[
            ("APP_ENV", "prod"),
            ("GATEWAY_TLS_CERT_FILE", pair.cert.to_str().unwrap()),
            ("GATEWAY_TLS_KEY_FILE", pair.key.to_str().unwrap()),
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn a_missing_key_file_of_the_tokens_exits_2_naming_the_variable() {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["check-config", "--mode", "gateway"],
        &[
            GATEWAY_ENVIRONMENT[0],
            ("JWT_PUBLIC_KEYS_FILE", "/nonexistent/keys.pem"),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).starts_with("JWT_PUBLIC_KEYS_FILE: "),
        "{}",
        stderr(&output)
    );
}

#[rstest]
#[case::a_zero_head_interval(
    &[("ANTI_ENTROPY_HEAD_INTERVAL", "0s")],
    "ANTI_ENTROPY_HEAD_INTERVAL: must be a positive duration such as 10m or 90d\n"
)]
#[case::a_zero_full_interval(
    &[("ANTI_ENTROPY_FULL_INTERVAL", "0s")],
    "ANTI_ENTROPY_FULL_INTERVAL: must be a positive duration such as 10m or 90d\n"
)]
#[case::a_full_interval_shorter_than_the_head_interval(
    &[("ANTI_ENTROPY_HEAD_INTERVAL", "30s"), ("ANTI_ENTROPY_FULL_INTERVAL", "10s")],
    "ANTI_ENTROPY_FULL_INTERVAL: must not be shorter than ANTI_ENTROPY_HEAD_INTERVAL\n"
)]
fn an_invalid_anti_entropy_interval_exits_2_naming_the_variable(
    #[case] extra: &[(&str, &str)],
    #[case] problems: &str,
) {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, extra);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), problems);
}

#[rstest]
#[case::a_zero_chunk_size(
    &[("BULK_CHUNK_ENTITIES", "0")],
    "BULK_CHUNK_ENTITIES: must be an integer from 1 to 1000\n"
)]
#[case::a_chunk_size_above_one_thousand(
    &[("BULK_CHUNK_ENTITIES", "1001")],
    "BULK_CHUNK_ENTITIES: must be an integer from 1 to 1000\n"
)]
#[case::a_zero_rate(
    &[("BULK_MAX_RECORDS_PER_SECOND", "0")],
    "BULK_MAX_RECORDS_PER_SECOND: must be an integer of at least 1\n"
)]
fn an_invalid_bulk_setting_exits_2_naming_the_variable(
    #[case] extra: &[(&str, &str)],
    #[case] problems: &str,
) {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, extra);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), problems);
}

#[rstest]
#[case::zero(&[("ROUTE_CONFIGURATION_MAX_ROUTES", "0")])]
#[case::above_one_thousand(&[("ROUTE_CONFIGURATION_MAX_ROUTES", "1001")])]
fn an_invalid_route_configuration_limit_exits_2_naming_the_variable(
    #[case] extra: &[(&str, &str)],
) {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, extra);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "ROUTE_CONFIGURATION_MAX_ROUTES: must be an integer from 1 to 1000\n"
    );
}

#[test]
fn the_route_configuration_limit_at_its_bounds_is_accepted() {
    let scratch = Scratch::new();

    let output = check_config_with(&scratch, &[("ROUTE_CONFIGURATION_MAX_ROUTES", "1")]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn bulk_settings_at_their_bounds_are_accepted() {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("BULK_CHUNK_ENTITIES", "1000"),
            ("BULK_MAX_RECORDS_PER_SECOND", "1"),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}

#[test]
fn anti_entropy_intervals_within_their_rules_are_accepted() {
    let scratch = Scratch::new();

    let output = check_config_with(
        &scratch,
        &[
            ("ANTI_ENTROPY_HEAD_INTERVAL", "2s"),
            ("ANTI_ENTROPY_FULL_INTERVAL", "2s"),
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "configuration OK\n");
}
