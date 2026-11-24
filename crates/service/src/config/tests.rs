use std::path::Path;

use rstest::rstest;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;

use super::*;

mod endpoints;

fn valid() -> ServeArgs {
    ServeArgs {
        database: DatabaseArgs {
            url: Some("postgres://app:secret@localhost:5432/app".to_owned()),
            ..DatabaseArgs::default()
        },
        aws_region: Some("us-east-1".to_owned()),
        tokens: TokenArgs {
            public_keys_file: Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned()),
            ..TokenArgs::default()
        },
        kafka: KafkaArgs {
            bootstrap_servers: Some("kafka-1:9094,kafka-2:9094".to_owned()),
            sasl_username: Some("iam-control".to_owned()),
            sasl_password: Some("secret-password".to_owned()),
            ..KafkaArgs::default()
        },
        ..ServeArgs::default()
    }
}

/// Writes `text` to a key file of this test process and returns its path.
fn key_file_with(name: &str, text: &str) -> String {
    let path =
        std::env::temp_dir().join(format!("service-config-{}-{name}.pem", std::process::id()));
    std::fs::write(&path, text).unwrap();
    path.to_string_lossy().into_owned()
}

fn development_key() -> String {
    std::fs::read_to_string(DEVELOPMENT_PUBLIC_KEYS_FILE).unwrap()
}

fn with_key_file(path: String) -> ServeArgs {
    let mut args = valid();
    args.tokens.public_keys_file = Some(path);
    args
}

fn some(value: &str) -> Option<String> {
    Option::from(value.to_owned())
}

fn problems(args: ServeArgs) -> Vec<(&'static str, String)> {
    Config::from_args(args)
        .unwrap_err()
        .problems()
        .iter()
        .map(|problem| (problem.variable, problem.reason.clone()))
        .collect()
}

fn variables(args: ServeArgs) -> Vec<&'static str> {
    problems(args)
        .into_iter()
        .map(|(variable, _reason)| variable)
        .collect()
}

#[test]
fn the_defaults_are_the_documented_ones() {
    let config = Config::from_args(valid()).unwrap();

    assert_eq!(config.app_env, AppEnv::Prod);
    assert_eq!(config.host, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(config.port, 8081);
    assert_eq!(config.log_level, "info");
    assert_eq!(
        config.database.url,
        "postgres://app:secret@localhost:5432/app"
    );
    assert_eq!(config.database.max_connections, 10);
    assert_eq!(config.database.acquire_timeout, Duration::from_secs(2));
    assert_eq!(config.database.statement_timeout, Duration::from_secs(5));
    assert_eq!(config.sqs.region, "us-east-1");
    assert_eq!(config.sqs.endpoint_url, None);
    assert_eq!(config.sqs.connect_timeout, Duration::from_millis(500));
    assert_eq!(config.sqs.operation_timeout, Duration::from_secs(2));
    assert_eq!(config.sqs.max_attempts, 1);
    assert_eq!(config.health_probe_timeout, Duration::from_secs(3));
    assert_eq!(config.request_timeout, Duration::from_secs(10));
    assert_eq!(config.max_body_bytes, 65_536);
    assert_eq!(config.shutdown_grace_period, Duration::from_secs(10));
    assert_eq!(
        config.tokens.public_keys_file,
        Path::new(DEVELOPMENT_PUBLIC_KEYS_FILE)
    );
    assert_eq!(config.tokens.jwt.issuer, "vilnacrm-user-service");
    assert_eq!(config.tokens.jwt.audience, "vilnacrm-api");
    assert_eq!(
        config.tokens.jwt.lifetime,
        TokenLifetimeRule::new(Duration::from_mins(15), Duration::from_secs(30))
    );
}

#[test]
fn the_token_settings_accept_valid_values() {
    let mut args = valid();
    args.tokens.issuer = some("issuer");
    args.tokens.audience = some("audience");
    args.tokens.clock_skew = some("60s");
    args.tokens.max_token_lifetime = some("1s");

    let tokens = Config::from_args(args).unwrap().tokens;

    assert_eq!(tokens.jwt.issuer, "issuer");
    assert_eq!(tokens.jwt.audience, "audience");
    assert_eq!(
        tokens.jwt.lifetime,
        TokenLifetimeRule::new(Duration::from_secs(1), Duration::from_secs(60))
    );
}

#[test]
fn the_key_file_is_required() {
    let mut args = valid();
    args.tokens.public_keys_file = None;

    assert_eq!(
        problems(args),
        [("JWT_PUBLIC_KEYS_FILE", "is required".to_owned())]
    );
}

#[test]
fn a_clock_skew_above_sixty_seconds_is_rejected() {
    let mut args = valid();
    args.tokens.clock_skew = some("61s");

    assert_eq!(
        problems(args),
        [(
            "JWT_CLOCK_SKEW",
            "must be a duration of at most 60s".to_owned()
        )]
    );
}

#[test]
fn the_token_memo_defaults_to_200000_identities_for_900_seconds() {
    let memo = Config::from_args(valid()).unwrap().tokens.memo;

    assert_eq!(
        memo,
        TokenMemoSettings {
            capacity: 200_000,
            max_ttl: Duration::from_mins(15),
        }
    );
}

#[test]
fn the_token_memo_accepts_its_bounds() {
    let mut args = valid();
    args.tokens.memo_capacity = some("1000");
    args.tokens.max_token_lifetime = some("10m");
    args.tokens.memo_max_ttl = some("10m");

    let memo = Config::from_args(args).unwrap().tokens.memo;

    assert_eq!(
        memo,
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(10),
        }
    );
}

#[test]
fn an_unset_memo_ttl_is_capped_at_a_shorter_max_token_lifetime() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("2m");

    let memo = Config::from_args(args).unwrap().tokens.memo;

    assert_eq!(memo.max_ttl, Duration::from_mins(2));
}

#[rstest]
#[case("999")]
#[case("0")]
#[case("-1")]
fn a_token_memo_capacity_below_1000_is_rejected(#[case] capacity: &str) {
    let mut args = valid();
    args.tokens.memo_capacity = some(capacity);

    assert_eq!(
        problems(args),
        [(
            "TOKEN_MEMO_CAPACITY",
            "must be an integer of at least 1000".to_owned()
        )]
    );
}

#[test]
fn a_token_memo_ttl_above_max_token_lifetime_is_rejected() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("10m");
    args.tokens.memo_max_ttl = some("601s");

    assert_eq!(
        problems(args),
        [(
            "TOKEN_MEMO_MAX_TTL",
            "must be a duration of at most MAX_TOKEN_LIFETIME".to_owned()
        )]
    );
}

#[test]
fn a_token_memo_ttl_is_not_compared_with_an_invalid_max_token_lifetime() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("x");
    args.tokens.memo_max_ttl = some("1h");

    assert_eq!(variables(args), ["MAX_TOKEN_LIFETIME"]);
}

#[test]
fn the_caller_rule_defaults_to_the_iam_audience_and_900_seconds() {
    let callers = Config::from_args(valid()).unwrap().tokens.callers;

    assert_eq!(
        callers,
        CallerTokenRule::new("vilnacrm-iam".to_owned(), Duration::from_mins(15))
    );
}

#[test]
fn the_caller_rule_takes_its_settings() {
    let mut args = valid();
    args.tokens.caller_audience = some("iam-callers");
    args.tokens.max_token_lifetime = some("1h");
    args.tokens.service_token_max_lifetime = some("1h");

    let callers = Config::from_args(args).unwrap().tokens.callers;

    assert_eq!(
        callers,
        CallerTokenRule::new("iam-callers".to_owned(), Duration::from_hours(1))
    );
}

#[test]
fn a_service_token_lifetime_of_one_second_is_accepted() {
    let mut args = valid();
    args.tokens.service_token_max_lifetime = some("1s");

    let callers = Config::from_args(args).unwrap().tokens.callers;

    assert_eq!(callers.max_service_lifetime(), Duration::from_secs(1));
}

#[test]
fn an_unset_service_token_lifetime_is_capped_at_a_shorter_max_token_lifetime() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("2m");

    let callers = Config::from_args(args).unwrap().tokens.callers;

    assert_eq!(callers.max_service_lifetime(), Duration::from_mins(2));
}

#[rstest]
#[case::above_one_hour("2h", "3601s")]
#[case::above_max_token_lifetime("15m", "901s")]
#[case::below_one_second("15m", "999ms")]
fn a_service_token_lifetime_out_of_bounds_is_rejected(
    #[case] max_token_lifetime: &str,
    #[case] service_lifetime: &str,
) {
    let mut args = valid();
    args.tokens.max_token_lifetime = some(max_token_lifetime);
    args.tokens.service_token_max_lifetime = some(service_lifetime);

    assert_eq!(
        problems(args),
        [(
            "JWT_SERVICE_TOKEN_MAX_LIFETIME",
            "must be a duration of at least 1s, at most 3600s and at most MAX_TOKEN_LIFETIME"
                .to_owned()
        )]
    );
}

#[test]
fn a_service_token_lifetime_is_not_compared_with_an_invalid_max_token_lifetime() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("x");
    args.tokens.service_token_max_lifetime = some("30m");

    assert_eq!(variables(args), ["MAX_TOKEN_LIFETIME"]);
}

#[test]
fn a_blank_caller_audience_is_rejected() {
    let mut args = valid();
    args.tokens.caller_audience = some(" ");

    assert_eq!(
        problems(args),
        [("JWT_CALLER_AUDIENCE", "must not be empty".to_owned())]
    );
}

#[test]
fn a_max_token_lifetime_below_one_second_is_rejected() {
    let mut args = valid();
    args.tokens.max_token_lifetime = some("999ms");

    assert_eq!(
        problems(args),
        [(
            "MAX_TOKEN_LIFETIME",
            "must be a duration of at least 1s".to_owned()
        )]
    );
}

#[rstest]
#[case("issuer")]
#[case("audience")]
fn a_blank_issuer_or_audience_is_rejected(#[case] which: &str) {
    let mut args = valid();
    if which == "issuer" {
        args.tokens.issuer = some(" ");
    } else {
        args.tokens.audience = some("");
    }

    let expected = if which == "issuer" {
        "JWT_ISSUER"
    } else {
        "JWT_AUDIENCE"
    };
    assert_eq!(problems(args), [(expected, "must not be empty".to_owned())]);
}

#[test]
fn a_key_file_with_up_to_three_keys_is_accepted() {
    let key = development_key();
    let path = key_file_with("three-keys", &key.repeat(3));

    let tokens = Config::from_args(with_key_file(path.clone()))
        .unwrap()
        .tokens;

    assert_eq!(tokens.public_keys_file, Path::new(&path));
}

#[rstest]
#[case::no_key("no-key", String::new(), "the key file holds no PEM key")]
#[case::four_keys(
    "four-keys",
    development_key().repeat(4),
    "the key file holds 4 keys, but at most 3 are allowed"
)]
#[case::unparsable(
    "unparsable",
    "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n".to_owned(),
    "key 1 of the key file is not a parsable RSA public key in PEM form"
)]
fn a_key_file_the_service_cannot_use_names_the_variable(
    #[case] name: &str,
    #[case] text: String,
    #[case] cause: &str,
) {
    let path = key_file_with(name, &text);

    assert_eq!(
        problems(with_key_file(path)),
        [(
            "JWT_PUBLIC_KEYS_FILE",
            format!("must name a file of 1 to 3 PEM RSA public keys: {cause}")
        )]
    );
}

#[test]
fn a_missing_key_file_is_reported_without_its_path() {
    let path = std::env::temp_dir()
        .join("service-config-no-such-secret-file.pem")
        .to_string_lossy()
        .into_owned();

    let reported = problems(with_key_file(path));

    assert_eq!(
        reported,
        [(
            "JWT_PUBLIC_KEYS_FILE",
            "must name a file of 1 to 3 PEM RSA public keys: the key file cannot be read"
                .to_owned()
        )]
    );
}

#[test]
fn every_variable_accepts_a_valid_value() {
    let args = ServeArgs {
        app_env: some("dev"),
        app_host: some("127.0.0.1"),
        app_port: some("9000"),
        log_level: some("service=debug,warn"),
        database: DatabaseArgs {
            url: some("postgresql://u:p@db:5433/name"),
            max_connections: some("25"),
            acquire_timeout: some("1s"),
            statement_timeout: some("750ms"),
        },
        aws_region: some("eu-west-1"),
        aws_endpoint_url_sqs: some("http://localhost:4566"),
        aws_access_key_id: some("key"),
        aws_secret_access_key: some("secret"),
        sqs_connect_timeout: some("300ms"),
        sqs_operation_timeout: some("1s"),
        sqs_max_attempts: some("3"),
        health_probe_timeout: some("4s"),
        http_request_timeout: some("1m"),
        http_max_body_bytes: some("2048"),
        shutdown_grace_period: some("15s"),
        tokens: valid().tokens,
        kafka: valid().kafka,
        maintenance: valid().maintenance,
        relay: valid().relay,
        anti_entropy: valid().anti_entropy,
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(config.app_env, AppEnv::Dev);
    assert_eq!(config.host, IpAddr::from([127, 0, 0, 1]));
    assert_eq!(config.port, 9000);
    assert_eq!(config.log_level, "service=debug,warn");
    assert_eq!(config.database.url, "postgresql://u:p@db:5433/name");
    assert_eq!(config.database.max_connections, 25);
    assert_eq!(config.database.acquire_timeout, Duration::from_secs(1));
    assert_eq!(
        config.database.statement_timeout,
        Duration::from_millis(750)
    );
    assert_eq!(config.sqs.region, "eu-west-1");
    assert_eq!(
        config.sqs.endpoint_url.as_deref(),
        Some("http://localhost:4566")
    );
    assert_eq!(config.sqs.connect_timeout, Duration::from_millis(300));
    assert_eq!(config.sqs.operation_timeout, Duration::from_secs(1));
    assert_eq!(config.sqs.max_attempts, 3);
    assert_eq!(config.health_probe_timeout, Duration::from_secs(4));
    assert_eq!(config.request_timeout, Duration::from_secs(60));
    assert_eq!(config.max_body_bytes, 2048);
    assert_eq!(config.shutdown_grace_period, Duration::from_secs(15));
}

#[rstest]
#[case("dev", AppEnv::Dev)]
#[case("test", AppEnv::Test)]
#[case("prod", AppEnv::Prod)]
fn app_env_accepts_its_three_values(#[case] raw: &str, #[case] expected: AppEnv) {
    let args = ServeArgs {
        app_env: some(raw),
        ..valid()
    };

    assert_eq!(Config::from_args(args).unwrap().app_env, expected);
}

#[rstest]
#[case("staging")]
#[case("")]
#[case("Dev")]
fn app_env_rejects_anything_else(#[case] raw: &str) {
    let args = ServeArgs {
        app_env: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("APP_ENV", "must be one of dev, test, prod".to_owned())]
    );
}

#[rstest]
#[case("::1")]
#[case("10.1.2.3")]
fn app_host_accepts_ip_addresses(#[case] raw: &str) {
    let args = ServeArgs {
        app_host: some(raw),
        ..valid()
    };

    assert_eq!(
        Config::from_args(args).unwrap().host,
        raw.parse::<IpAddr>().unwrap()
    );
}

#[rstest]
#[case("localhost")]
#[case("")]
#[case("256.1.1.1")]
fn app_host_rejects_what_is_not_an_ip_address(#[case] raw: &str) {
    let args = ServeArgs {
        app_host: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("APP_HOST", "must be an IP address".to_owned())]
    );
}

#[rstest]
#[case("0", 0)]
#[case("65535", 65535)]
fn app_port_accepts_the_whole_range(#[case] raw: &str, #[case] expected: u16) {
    let args = ServeArgs {
        app_port: some(raw),
        ..valid()
    };

    assert_eq!(Config::from_args(args).unwrap().port, expected);
}

#[rstest]
#[case("65536")]
#[case("99999")]
#[case("-1")]
#[case("eighty")]
#[case("")]
fn app_port_rejects_the_rest(#[case] raw: &str) {
    let args = ServeArgs {
        app_port: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("APP_PORT", "must be an integer from 0 to 65535".to_owned())]
    );
}

#[rstest]
#[case("debug")]
#[case("warn,service=trace")]
fn log_level_accepts_filter_directives(#[case] raw: &str) {
    let args = ServeArgs {
        log_level: some(raw),
        ..valid()
    };

    assert_eq!(Config::from_args(args).unwrap().log_level, raw);
}

#[rstest]
#[case("service=loud")]
#[case("info,=debug")]
fn log_level_rejects_invalid_directives(#[case] raw: &str) {
    let args = ServeArgs {
        log_level: some(raw),
        ..valid()
    };

    assert_eq!(variables(args), ["LOG_LEVEL"]);
}

#[test]
fn the_database_url_is_required() {
    let args = ServeArgs {
        database: DatabaseArgs::default(),
        ..valid()
    };

    assert_eq!(problems(args), [("DATABASE_URL", "is required".to_owned())]);
}

#[test]
fn a_blank_required_variable_is_reported_as_empty() {
    let args = ServeArgs {
        aws_region: some("  "),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("AWS_REGION", "must not be empty".to_owned())]
    );
}

#[rstest]
#[case("mysql://user:hunter2@h/db")]
#[case("not a url")]
#[case("http://localhost/db")]
#[case("")]
fn the_database_url_must_be_a_postgres_url_and_is_never_echoed(#[case] raw: &str) {
    let args = ServeArgs {
        database: DatabaseArgs {
            url: some(raw),
            ..DatabaseArgs::default()
        },
        ..valid()
    };

    let found = problems(args);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "DATABASE_URL");
    assert!(!found[0].1.contains("hunter2"));
}

#[rstest]
#[case("1", 1)]
#[case("100", 100)]
fn database_max_connections_accepts_its_bounds(#[case] raw: &str, #[case] expected: u32) {
    let args = ServeArgs {
        database: DatabaseArgs {
            max_connections: some(raw),
            ..valid().database
        },
        ..valid()
    };

    assert_eq!(
        Config::from_args(args).unwrap().database.max_connections,
        expected
    );
}

#[rstest]
#[case("0")]
#[case("101")]
#[case("-1")]
#[case("many")]
fn database_max_connections_rejects_values_outside_the_range(#[case] raw: &str) {
    let args = ServeArgs {
        database: DatabaseArgs {
            max_connections: some(raw),
            ..valid().database
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "DATABASE_MAX_CONNECTIONS",
            "must be an integer from 1 to 100".to_owned()
        )]
    );
}

#[test]
fn an_unparsable_duration_names_its_variable() {
    let args = ServeArgs {
        database: DatabaseArgs {
            acquire_timeout: some("soon"),
            statement_timeout: some("5"),
            ..valid().database
        },
        sqs_connect_timeout: some(""),
        sqs_operation_timeout: some("-2s"),
        health_probe_timeout: some("fast"),
        http_request_timeout: some("1 fortnight"),
        shutdown_grace_period: some("later"),
        ..valid()
    };

    let found = problems(args);

    assert_eq!(
        found
            .iter()
            .map(|(variable, _)| *variable)
            .collect::<Vec<_>>(),
        [
            "DATABASE_ACQUIRE_TIMEOUT",
            "DATABASE_STATEMENT_TIMEOUT",
            "SQS_CONNECT_TIMEOUT",
            "SQS_OPERATION_TIMEOUT",
            "HEALTH_PROBE_TIMEOUT",
            "HTTP_REQUEST_TIMEOUT",
            "SHUTDOWN_GRACE_PERIOD",
        ]
    );
    assert!(
        found
            .iter()
            .all(|(_, reason)| reason == "must be a duration such as 500ms, 2s or 1m")
    );
}

#[rstest]
#[case("http://localhost:4566")]
#[case("https://sqs.eu-west-1.amazonaws.com")]
#[case("http://localstack:4566/")]
#[case("http://[::1]:4566")]
#[case("http://[::1]")]
#[case("http://user:secret@localstack:4566")]
#[case("http://localhost:0")]
#[case("http://localhost:65535")]
fn the_sqs_endpoint_accepts_http_and_https_urls(#[case] raw: &str) {
    let args = ServeArgs {
        aws_endpoint_url_sqs: some(raw),
        ..valid()
    };

    assert_eq!(
        Config::from_args(args).unwrap().sqs.endpoint_url.as_deref(),
        Some(raw)
    );
}

#[rstest]
#[case("ftp://localhost")]
#[case("localhost:4566")]
#[case("http://")]
#[case("https://")]
#[case("")]
#[case("http:// ")]
#[case("http://exa mple:4566")]
#[case("http://:4566")]
#[case("http://localhost:abc")]
#[case("http://localhost:99999")]
#[case("http://127.0.0.1:4566x")]
#[case("http://abc:abc")]
#[case("http://localhost:")]
#[case("http://user@localhost:4566x")]
#[case("http://[::1]x:80")]
#[case("http://[::1]x")]
#[case("http://localhost:+80")]
#[case("http://localhost:-1")]
fn the_sqs_endpoint_rejects_everything_else(#[case] raw: &str) {
    let args = ServeArgs {
        aws_endpoint_url_sqs: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "AWS_ENDPOINT_URL_SQS",
            "must be an http:// or https:// URL".to_owned()
        )]
    );
}

#[test]
fn the_migrate_wait_timeout_defaults_to_thirty_seconds() {
    let args = MigrateArgs {
        database: valid().database,
        wait_timeout: None,
        action: None,
    };

    let settings = MigrateSettings::from_args(&args).unwrap();

    assert_eq!(settings.wait_timeout, Duration::from_secs(30));
    assert_eq!(
        settings.database.url,
        "postgres://app:secret@localhost:5432/app"
    );
}

#[test]
fn aws_region_is_required() {
    let args = ServeArgs {
        aws_region: None,
        ..valid()
    };

    assert_eq!(problems(args), [("AWS_REGION", "is required".to_owned())]);
}

#[rstest]
#[case("1", 1)]
#[case("5", 5)]
fn sqs_max_attempts_accepts_its_bounds(#[case] raw: &str, #[case] expected: u32) {
    let args = ServeArgs {
        sqs_max_attempts: some(raw),
        ..valid()
    };

    assert_eq!(Config::from_args(args).unwrap().sqs.max_attempts, expected);
}

#[rstest]
#[case("0")]
#[case("6")]
#[case("x")]
fn sqs_max_attempts_rejects_values_outside_the_range(#[case] raw: &str) {
    let args = ServeArgs {
        sqs_max_attempts: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "SQS_MAX_ATTEMPTS",
            "must be an integer from 1 to 5".to_owned()
        )]
    );
}

#[rstest]
#[case("1024", 1024)]
#[case("10485760", 10_485_760)]
fn http_max_body_bytes_accepts_its_bounds(#[case] raw: &str, #[case] expected: usize) {
    let args = ServeArgs {
        http_max_body_bytes: some(raw),
        ..valid()
    };

    assert_eq!(Config::from_args(args).unwrap().max_body_bytes, expected);
}

#[rstest]
#[case("1023")]
#[case("10485761")]
#[case("big")]
fn http_max_body_bytes_rejects_values_outside_the_range(#[case] raw: &str) {
    let args = ServeArgs {
        http_max_body_bytes: some(raw),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "HTTP_MAX_BODY_BYTES",
            "must be an integer from 1024 to 10485760".to_owned()
        )]
    );
}

#[test]
fn credentials_set_together_or_not_at_all_are_valid() {
    let both = ServeArgs {
        aws_access_key_id: some("key"),
        aws_secret_access_key: some("secret"),
        ..valid()
    };

    assert!(Config::from_args(both).is_ok());
    assert!(Config::from_args(valid()).is_ok());
}

#[test]
fn a_key_id_without_a_secret_names_the_missing_secret() {
    let args = ServeArgs {
        aws_access_key_id: some("key"),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "AWS_SECRET_ACCESS_KEY",
            "is required when AWS_ACCESS_KEY_ID is set".to_owned()
        )]
    );
}

#[test]
fn a_secret_without_a_key_id_names_the_missing_key_id() {
    let args = ServeArgs {
        aws_secret_access_key: some("secret"),
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "AWS_ACCESS_KEY_ID",
            "is required when AWS_SECRET_ACCESS_KEY is set".to_owned()
        )]
    );
}

fn timeouts(acquire: &str, operation: &str, probe: &str, request: &str) -> ServeArgs {
    ServeArgs {
        database: DatabaseArgs {
            acquire_timeout: some(acquire),
            ..valid().database
        },
        sqs_operation_timeout: some(operation),
        health_probe_timeout: some(probe),
        http_request_timeout: some(request),
        ..valid()
    }
}

#[test]
fn the_probe_timeout_may_equal_the_acquire_and_operation_timeouts() {
    assert!(Config::from_args(timeouts("3s", "3s", "3s", "4s")).is_ok());
}

#[test]
fn the_probe_timeout_below_the_acquire_timeout_is_reported() {
    assert_eq!(
        problems(timeouts("4s", "2s", "3s", "10s")),
        [(
            "HEALTH_PROBE_TIMEOUT",
            "must not be shorter than DATABASE_ACQUIRE_TIMEOUT".to_owned()
        )]
    );
}

#[test]
fn the_probe_timeout_below_the_operation_timeout_is_reported() {
    assert_eq!(
        problems(timeouts("2s", "4s", "3s", "10s")),
        [(
            "HEALTH_PROBE_TIMEOUT",
            "must not be shorter than SQS_OPERATION_TIMEOUT".to_owned()
        )]
    );
}

#[test]
fn the_request_timeout_must_exceed_the_probe_timeout() {
    assert_eq!(
        problems(timeouts("2s", "2s", "3s", "3s")),
        [(
            "HTTP_REQUEST_TIMEOUT",
            "must be longer than HEALTH_PROBE_TIMEOUT".to_owned()
        )]
    );
    assert!(Config::from_args(timeouts("2s", "2s", "3s", "3001ms")).is_ok());
}

#[rstest]
#[case::zero("0s")]
#[case::bare_zero("0")]
#[case::below_a_millisecond("500us")]
#[case::above_the_range("30d")]
#[case::just_above_the_range("24d 1s")]
fn a_statement_timeout_outside_one_millisecond_to_24_days_is_rejected(#[case] value: &str) {
    let args = ServeArgs {
        database: DatabaseArgs {
            statement_timeout: some(value),
            ..valid().database
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "DATABASE_STATEMENT_TIMEOUT",
            "must be a duration from 1ms to 24d".to_owned()
        )]
    );
}

#[rstest]
#[case::lower_bound("1ms", Duration::from_millis(1))]
#[case::upper_bound("24d", Duration::from_hours(24 * 24))]
#[case::default_like("5s", Duration::from_secs(5))]
fn a_statement_timeout_inside_the_range_is_accepted(
    #[case] value: &str,
    #[case] expected: Duration,
) {
    let args = ServeArgs {
        database: DatabaseArgs {
            statement_timeout: some(value),
            ..valid().database
        },
        ..valid()
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(config.database.statement_timeout, expected);
}

#[test]
fn a_timeout_above_its_prd_ceiling_is_accepted() {
    let args = ServeArgs {
        database: DatabaseArgs {
            acquire_timeout: some("1m"),
            statement_timeout: some("10m"),
            ..valid().database
        },
        sqs_operation_timeout: some("1m"),
        health_probe_timeout: some("2m"),
        http_request_timeout: some("5m"),
        shutdown_grace_period: some("10m"),
        http_max_body_bytes: some("10485760"),
        ..valid()
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(config.database.acquire_timeout, Duration::from_secs(60));
    assert_eq!(config.health_probe_timeout, Duration::from_secs(120));
    assert_eq!(config.shutdown_grace_period, Duration::from_secs(600));
}

#[test]
fn a_rule_between_two_variables_is_skipped_when_one_of_them_is_invalid() {
    let args = ServeArgs {
        health_probe_timeout: some("soon"),
        http_request_timeout: some("1s"),
        ..valid()
    };

    assert_eq!(variables(args), ["HEALTH_PROBE_TIMEOUT"]);
}

#[test]
fn every_problem_is_reported_in_one_run_in_the_order_of_the_table() {
    let args = ServeArgs {
        app_env: some("staging"),
        app_port: some("99999"),
        database: DatabaseArgs {
            url: some("mysql://user:hunter2@h/db"),
            ..DatabaseArgs::default()
        },
        aws_region: None,
        aws_access_key_id: some("key"),
        tokens: valid().tokens,
        kafka: valid().kafka,
        ..ServeArgs::default()
    };

    let errors = Config::from_args(args).unwrap_err();

    assert_eq!(
        errors
            .problems()
            .iter()
            .map(|problem| problem.variable)
            .collect::<Vec<_>>(),
        [
            "APP_ENV",
            "APP_PORT",
            "DATABASE_URL",
            "AWS_REGION",
            "AWS_SECRET_ACCESS_KEY"
        ]
    );
    assert_eq!(
        errors.to_string(),
        "the configuration is invalid (5 problem(s))"
    );
    assert!(
        errors
            .problems()
            .iter()
            .all(|problem| !problem.reason.contains("hunter2"))
    );
}

type Mutator = fn(&mut ServeArgs);

/// One row per variable of `ServeArgs`: the variable, a way to make it the only problem, and the
/// variable that the problem names.
const FIELDS: [(&str, Mutator, &str); 48] = [
    ("APP_ENV", |a| a.app_env = some("x"), "APP_ENV"),
    ("APP_HOST", |a| a.app_host = some("x"), "APP_HOST"),
    ("APP_PORT", |a| a.app_port = some("x"), "APP_PORT"),
    ("LOG_LEVEL", |a| a.log_level = some("x=y"), "LOG_LEVEL"),
    ("DATABASE_URL", |a| a.database.url = None, "DATABASE_URL"),
    (
        "DATABASE_MAX_CONNECTIONS",
        |a| a.database.max_connections = some("x"),
        "DATABASE_MAX_CONNECTIONS",
    ),
    (
        "DATABASE_ACQUIRE_TIMEOUT",
        |a| a.database.acquire_timeout = some("x"),
        "DATABASE_ACQUIRE_TIMEOUT",
    ),
    (
        "DATABASE_STATEMENT_TIMEOUT",
        |a| a.database.statement_timeout = some("x"),
        "DATABASE_STATEMENT_TIMEOUT",
    ),
    ("AWS_REGION", |a| a.aws_region = None, "AWS_REGION"),
    (
        "AWS_ENDPOINT_URL_SQS",
        |a| a.aws_endpoint_url_sqs = some("x"),
        "AWS_ENDPOINT_URL_SQS",
    ),
    (
        "AWS_ACCESS_KEY_ID",
        |a| a.aws_access_key_id = some("x"),
        "AWS_SECRET_ACCESS_KEY",
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        |a| a.aws_secret_access_key = some("x"),
        "AWS_ACCESS_KEY_ID",
    ),
    (
        "SQS_CONNECT_TIMEOUT",
        |a| a.sqs_connect_timeout = some("x"),
        "SQS_CONNECT_TIMEOUT",
    ),
    (
        "SQS_OPERATION_TIMEOUT",
        |a| a.sqs_operation_timeout = some("x"),
        "SQS_OPERATION_TIMEOUT",
    ),
    (
        "SQS_MAX_ATTEMPTS",
        |a| a.sqs_max_attempts = some("x"),
        "SQS_MAX_ATTEMPTS",
    ),
    (
        "HEALTH_PROBE_TIMEOUT",
        |a| a.health_probe_timeout = some("x"),
        "HEALTH_PROBE_TIMEOUT",
    ),
    (
        "HTTP_REQUEST_TIMEOUT",
        |a| a.http_request_timeout = some("x"),
        "HTTP_REQUEST_TIMEOUT",
    ),
    (
        "HTTP_MAX_BODY_BYTES",
        |a| a.http_max_body_bytes = some("x"),
        "HTTP_MAX_BODY_BYTES",
    ),
    (
        "SHUTDOWN_GRACE_PERIOD",
        |a| a.shutdown_grace_period = some("x"),
        "SHUTDOWN_GRACE_PERIOD",
    ),
    (
        "JWT_PUBLIC_KEYS_FILE",
        |a| a.tokens.public_keys_file = None,
        "JWT_PUBLIC_KEYS_FILE",
    ),
    ("JWT_ISSUER", |a| a.tokens.issuer = some(""), "JWT_ISSUER"),
    (
        "JWT_AUDIENCE",
        |a| a.tokens.audience = some(""),
        "JWT_AUDIENCE",
    ),
    (
        "JWT_CLOCK_SKEW",
        |a| a.tokens.clock_skew = some("x"),
        "JWT_CLOCK_SKEW",
    ),
    (
        "MAX_TOKEN_LIFETIME",
        |a| a.tokens.max_token_lifetime = some("x"),
        "MAX_TOKEN_LIFETIME",
    ),
    (
        "TOKEN_MEMO_CAPACITY",
        |a| a.tokens.memo_capacity = some("x"),
        "TOKEN_MEMO_CAPACITY",
    ),
    (
        "TOKEN_MEMO_MAX_TTL",
        |a| a.tokens.memo_max_ttl = some("x"),
        "TOKEN_MEMO_MAX_TTL",
    ),
    (
        "JWT_CALLER_AUDIENCE",
        |a| a.tokens.caller_audience = some(""),
        "JWT_CALLER_AUDIENCE",
    ),
    (
        "JWT_SERVICE_TOKEN_MAX_LIFETIME",
        |a| a.tokens.service_token_max_lifetime = some("x"),
        "JWT_SERVICE_TOKEN_MAX_LIFETIME",
    ),
    (
        "KAFKA_BOOTSTRAP_SERVERS",
        |a| a.kafka.bootstrap_servers = None,
        "KAFKA_BOOTSTRAP_SERVERS",
    ),
    (
        "KAFKA_SECURITY_PROTOCOL",
        |a| a.kafka.security_protocol = some("x"),
        "KAFKA_SECURITY_PROTOCOL",
    ),
    (
        "KAFKA_SASL_MECHANISM",
        |a| a.kafka.sasl_mechanism = some("x"),
        "KAFKA_SASL_MECHANISM",
    ),
    (
        "KAFKA_SASL_USERNAME",
        |a| a.kafka.sasl_username = None,
        "KAFKA_SASL_USERNAME",
    ),
    (
        "KAFKA_SASL_PASSWORD",
        |a| a.kafka.sasl_password = None,
        "KAFKA_SASL_PASSWORD",
    ),
    (
        "KAFKA_CA_FILE",
        |a| a.kafka.ca_file = some(""),
        "KAFKA_CA_FILE",
    ),
    (
        "KAFKA_CLIENT_ID",
        |a| a.kafka.client_id = some(""),
        "KAFKA_CLIENT_ID",
    ),
    (
        "KAFKA_CONNECT_TIMEOUT",
        |a| a.kafka.connect_timeout = some("x"),
        "KAFKA_CONNECT_TIMEOUT",
    ),
    (
        "KAFKA_REQUEST_TIMEOUT",
        |a| a.kafka.request_timeout = some("x"),
        "KAFKA_REQUEST_TIMEOUT",
    ),
    (
        "KAFKA_RETRY_DELAY",
        |a| a.kafka.retry_delay = some("x"),
        "KAFKA_RETRY_DELAY",
    ),
    (
        "MAINTENANCE_INTERVAL",
        |a| a.maintenance.interval = some("x"),
        "MAINTENANCE_INTERVAL",
    ),
    (
        "ORPHANED_GRANT_RETENTION",
        |a| a.maintenance.orphaned_grant_retention = some("x"),
        "ORPHANED_GRANT_RETENTION",
    ),
    (
        "DATABASE_LISTEN_URL",
        |a| a.relay.listen_url = some("mysql://x"),
        "DATABASE_LISTEN_URL",
    ),
    (
        "KAFKA_TRANSACTION_TIMEOUT",
        |a| a.relay.transaction_timeout = some("x"),
        "KAFKA_TRANSACTION_TIMEOUT",
    ),
    (
        "PUBLISH_WAIT_TIMEOUT",
        |a| a.relay.publish_wait_timeout = some("x"),
        "PUBLISH_WAIT_TIMEOUT",
    ),
    (
        "ANTI_ENTROPY_HEAD_INTERVAL",
        |a| a.anti_entropy.head_interval = some("x"),
        "ANTI_ENTROPY_HEAD_INTERVAL",
    ),
    (
        "ANTI_ENTROPY_FULL_INTERVAL",
        |a| a.anti_entropy.full_interval = some("x"),
        "ANTI_ENTROPY_FULL_INTERVAL",
    ),
    (
        "KAFKA_CONFIG_GATES",
        |a| a.kafka.config_gates = some("x"),
        "KAFKA_CONFIG_GATES",
    ),
    (
        "POLICY_TOPIC",
        |a| a.kafka.policy_topic = some("x y"),
        "POLICY_TOPIC",
    ),
    (
        "EVENTS_TOPIC",
        |a| a.kafka.events_topic = some("x y"),
        "EVENTS_TOPIC",
    ),
];

#[test]
fn every_field_of_serve_args_is_consumed_by_from_args() {
    use clap::{Args as _, Command};

    let declared: Vec<String> = ServeArgs::augment_args(Command::new("serve"))
        .get_arguments()
        .filter_map(|argument| argument.get_env())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    let mut tested: Vec<&str> = FIELDS.iter().map(|(variable, _, _)| *variable).collect();
    tested.sort_unstable();
    let mut declared: Vec<&str> = declared.iter().map(String::as_str).collect();
    declared.sort_unstable();
    assert_eq!(declared, tested);

    for (variable, mutate, reported) in FIELDS {
        let mut args = valid();
        mutate(&mut args);
        assert_eq!(variables(args), [reported], "{variable} is not consumed");
    }
}

#[test]
fn the_kafka_defaults_are_the_documented_ones() {
    let kafka = Config::from_args(valid()).unwrap().kafka;

    assert_eq!(kafka.bootstrap_servers, "kafka-1:9094,kafka-2:9094");
    assert_eq!(
        kafka.security,
        KafkaSecurity::SaslSsl {
            mechanism: SaslMechanism::ScramSha512,
            username: "iam-control".to_owned(),
            password: KafkaSecret::new("secret-password".to_owned()),
            ca_file: None,
        }
    );
    assert_eq!(kafka.client_id, "iam-control");
    assert_eq!(kafka.connect_timeout, Duration::from_secs(1));
    assert_eq!(kafka.request_timeout, Duration::from_secs(2));
    assert_eq!(kafka.retry_delay, Duration::from_millis(100));
    assert_eq!(kafka.gates, ConfigGates::Enforce);
    assert_eq!(kafka.policy_topic, "iam.policy.state.v1");
    assert_eq!(kafka.events_topic, "iam.events.v1");
}

#[test]
fn every_kafka_setting_accepts_a_valid_value() {
    let mut args = valid();
    args.app_env = some("dev");
    args.kafka = KafkaArgs {
        bootstrap_servers: some("localhost:9092"),
        security_protocol: some("SASL_SSL"),
        sasl_mechanism: some("SCRAM-SHA-256"),
        sasl_username: some("user"),
        sasl_password: some("password"),
        ca_file: some("/etc/kafka/ca.pem"),
        client_id: some("client"),
        connect_timeout: some("500ms"),
        request_timeout: some("1s"),
        retry_delay: some("50ms"),
        config_gates: some("relaxed"),
        policy_topic: some("state"),
        events_topic: some("events"),
    };

    let kafka = Config::from_args(args).unwrap().kafka;

    assert_eq!(
        kafka.security,
        KafkaSecurity::SaslSsl {
            mechanism: SaslMechanism::ScramSha256,
            username: "user".to_owned(),
            password: KafkaSecret::new("password".to_owned()),
            ca_file: Some("/etc/kafka/ca.pem".to_owned()),
        }
    );
    assert_eq!(kafka.gates, ConfigGates::Relaxed);
    assert_eq!(kafka.client_id, "client");
    assert_eq!(kafka.connect_timeout, Duration::from_millis(500));
    assert_eq!(kafka.request_timeout, Duration::from_secs(1));
    assert_eq!(kafka.retry_delay, Duration::from_millis(50));
    assert_eq!(
        (kafka.policy_topic.as_str(), kafka.events_topic.as_str()),
        ("state", "events")
    );
}

#[rstest]
#[case::dev("dev")]
#[case::test("test")]
fn plaintext_needs_no_credentials_and_relaxed_gates_pass_in_dev_and_test(
    #[case] environment: &str,
) {
    let mut args = valid();
    args.app_env = some(environment);
    args.kafka = KafkaArgs {
        bootstrap_servers: some("localhost:9092"),
        security_protocol: some("PLAINTEXT"),
        config_gates: some("relaxed"),
        ..KafkaArgs::default()
    };

    let kafka = Config::from_args(args).unwrap().kafka;

    assert_eq!(kafka.security, KafkaSecurity::Plaintext);
    assert_eq!(kafka.gates, ConfigGates::Relaxed);
}

#[test]
fn plaintext_and_relaxed_gates_are_refused_in_prod_and_without_an_environment() {
    for environment in [None, some("prod")] {
        let mut args = valid();
        args.app_env = environment;
        args.kafka.security_protocol = some("PLAINTEXT");
        args.kafka.config_gates = some("relaxed");

        assert_eq!(
            problems(args),
            [
                (
                    "KAFKA_SECURITY_PROTOCOL",
                    "must be SASL_SSL unless APP_ENV is dev or test".to_owned()
                ),
                (
                    "KAFKA_CONFIG_GATES",
                    "must be enforce unless APP_ENV is dev or test".to_owned()
                ),
            ]
        );
    }
}

#[test]
fn an_invalid_environment_does_not_add_kafka_environment_problems() {
    let mut args = valid();
    args.app_env = some("staging");
    args.kafka.security_protocol = some("PLAINTEXT");
    args.kafka.config_gates = some("relaxed");

    assert_eq!(variables(args), ["APP_ENV"]);
}

#[test]
fn the_sasl_settings_are_only_read_with_sasl_ssl() {
    let mut args = valid();
    args.app_env = some("dev");
    args.kafka.security_protocol = some("PLAINTEXT");
    args.kafka.sasl_mechanism = some("PLAIN");
    args.kafka.sasl_username = None;
    args.kafka.sasl_password = None;
    args.kafka.ca_file = some("");

    assert!(Config::from_args(args).is_ok());
}

#[rstest]
#[case::no_port("kafka-1")]
#[case::port_zero("kafka-1:0")]
#[case::port_too_large("kafka-1:65536")]
#[case::empty_host(":9092")]
#[case::empty_entry("kafka-1:9092,")]
#[case::a_space_in_the_host("kafka 1:9092")]
#[case::a_scheme("http://kafka-1:9092")]
fn a_bootstrap_list_that_is_not_host_port_pairs_is_rejected(#[case] list: &str) {
    let mut args = valid();
    args.kafka.bootstrap_servers = some(list);

    assert_eq!(
        problems(args),
        [(
            "KAFKA_BOOTSTRAP_SERVERS",
            "must be comma-separated host:port pairs".to_owned()
        )]
    );
}

#[test]
fn a_request_timeout_shorter_than_the_connect_timeout_is_rejected() {
    let mut args = valid();
    args.kafka.connect_timeout = some("3s");
    args.kafka.request_timeout = some("2s");

    assert_eq!(
        problems(args),
        [(
            "KAFKA_REQUEST_TIMEOUT",
            "must not be shorter than KAFKA_CONNECT_TIMEOUT".to_owned()
        )]
    );
}

#[rstest]
#[case::dot(".")]
#[case::dot_dot("..")]
#[case::a_slash("a/b")]
#[case::too_long(&"a".repeat(250))]
fn an_invalid_topic_name_is_rejected(#[case] name: &str) {
    let mut args = valid();
    args.kafka.policy_topic = some(name);

    assert_eq!(variables(args), ["POLICY_TOPIC"]);
}

#[test]
fn the_two_topics_must_differ() {
    let mut args = valid();
    args.kafka.policy_topic = some("topic");
    args.kafka.events_topic = some("topic");

    assert_eq!(
        problems(args),
        [("EVENTS_TOPIC", "must differ from POLICY_TOPIC".to_owned())]
    );
}

#[test]
fn a_kafka_problem_never_contains_the_password() {
    let mut args = valid();
    args.kafka.sasl_password = some("hunter2-kafka");
    args.kafka.sasl_mechanism = some("PLAIN");

    let errors = Config::from_args(args).unwrap_err();

    assert!(
        errors
            .problems()
            .iter()
            .all(|problem| !problem.reason.contains("hunter2-kafka"))
    );
}

fn valid_gateway() -> GatewayArgs {
    let mut args = GatewayArgs::default();
    args.service.app_env = some("test");
    args.service.tokens.public_keys_file = some(DEVELOPMENT_PUBLIC_KEYS_FILE);
    args
}

fn gateway_problems(args: &GatewayArgs) -> Vec<(&'static str, String)> {
    GatewayConfig::from_args(args)
        .unwrap_err()
        .problems()
        .iter()
        .map(|problem| (problem.variable, problem.reason.clone()))
        .collect()
}

fn gateway_variables(args: &GatewayArgs) -> Vec<&'static str> {
    gateway_problems(args)
        .into_iter()
        .map(|(variable, _reason)| variable)
        .collect()
}

fn certificate_pair(name: &str) -> (String, String) {
    let directory =
        std::env::temp_dir().join(format!("service-gateway-config-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let files = test_support::tls::self_signed(&directory, name, name);
    (
        files.cert.to_string_lossy().into_owned(),
        files.key.to_string_lossy().into_owned(),
    )
}

#[test]
fn the_gateway_defaults_are_the_documented_ones() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert_eq!(config.app_env, AppEnv::Test);
    assert_eq!(config.log_level, "info");
    assert_eq!(config.shutdown_grace_period, Duration::from_secs(10));
    assert_eq!(config.listen, "0.0.0.0:8443".parse::<SocketAddr>().unwrap());
    assert_eq!(
        config.internal_listen,
        "0.0.0.0:9090".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        config.probe_listen,
        "0.0.0.0:9092".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(config.tls, None);
    assert_eq!(config.pod_name, None);
    assert_eq!(config.pod_namespace, None);
    assert_eq!(
        config.tokens.public_keys_file,
        PathBuf::from(DEVELOPMENT_PUBLIC_KEYS_FILE)
    );
}

#[test]
fn the_gateway_needs_no_database_queue_or_kafka_setting() {
    let mut args = valid_gateway();
    args.service.database.url = some("not-a-url");
    args.service.aws_region = None;
    args.service.kafka.bootstrap_servers = some("???");

    assert!(GatewayConfig::from_args(&args).is_ok());
}

#[test]
fn the_control_configuration_still_names_the_database() {
    let args = valid_gateway();

    let problems = problems(args.service);

    assert!(
        problems
            .iter()
            .any(|(variable, _reason)| *variable == "DATABASE_URL")
    );
}

#[test]
fn the_gateway_takes_the_listeners_pod_and_grace_period_it_is_given() {
    let mut args = valid_gateway();
    args.listen = some("127.0.0.1:1");
    args.internal_listen = some("[::1]:2");
    args.probe_listen = some("127.0.0.1:3");
    args.pod_name = some("gateway-0");
    args.pod_namespace = some("iam");
    args.service.shutdown_grace_period = some("3s");

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(config.listen.port(), 1);
    assert_eq!(
        config.internal_listen,
        "[::1]:2".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(config.probe_listen.port(), 3);
    assert_eq!(config.pod_name.as_deref(), Some("gateway-0"));
    assert_eq!(config.pod_namespace.as_deref(), Some("iam"));
    assert_eq!(config.shutdown_grace_period, Duration::from_secs(3));
}

#[rstest]
#[case::internal_equals_public(
    "127.0.0.1:5000",
    "127.0.0.1:5000",
    "127.0.0.1:5002",
    "GATEWAY_INTERNAL_LISTEN"
)]
#[case::probe_equals_public(
    "127.0.0.1:5000",
    "127.0.0.1:5001",
    "127.0.0.1:5000",
    "GATEWAY_PROBE_LISTEN"
)]
#[case::probe_equals_internal(
    "127.0.0.1:5000",
    "127.0.0.1:5001",
    "127.0.0.1:5001",
    "GATEWAY_PROBE_LISTEN"
)]
fn equal_listener_addresses_are_refused_naming_the_variable(
    #[case] public: &str,
    #[case] internal: &str,
    #[case] probe: &str,
    #[case] variable: &str,
) {
    let mut args = valid_gateway();
    args.listen = some(public);
    args.internal_listen = some(internal);
    args.probe_listen = some(probe);

    assert_eq!(gateway_variables(&args), vec![variable]);
}

#[test]
fn port_0_never_clashes() {
    let mut args = valid_gateway();
    args.listen = some("127.0.0.1:0");
    args.internal_listen = some("127.0.0.1:0");
    args.probe_listen = some("127.0.0.1:0");

    assert!(GatewayConfig::from_args(&args).is_ok());
}

#[rstest]
#[case::public("GATEWAY_LISTEN")]
#[case::internal("GATEWAY_INTERNAL_LISTEN")]
#[case::probe("GATEWAY_PROBE_LISTEN")]
fn an_address_without_a_port_is_refused(#[case] variable: &str) {
    let mut args = valid_gateway();
    match variable {
        "GATEWAY_LISTEN" => args.listen = some("0.0.0.0"),
        "GATEWAY_INTERNAL_LISTEN" => args.internal_listen = some("0.0.0.0"),
        _ => args.probe_listen = some("0.0.0.0"),
    }

    assert_eq!(gateway_variables(&args), vec![variable]);
}

#[test]
fn tls_files_are_required_outside_dev_and_test() {
    let mut args = valid_gateway();
    args.service.app_env = None;

    assert_eq!(
        gateway_problems(&args),
        vec![
            (
                "GATEWAY_TLS_CERT_FILE",
                "is required outside APP_ENV dev and test".to_owned()
            ),
            (
                "GATEWAY_TLS_KEY_FILE",
                "is required outside APP_ENV dev and test".to_owned()
            ),
        ]
    );
}

#[rstest]
#[case::dev("dev")]
#[case::test("test")]
fn dev_and_test_accept_plain_http_without_the_files(#[case] env: &str) {
    let mut args = valid_gateway();
    args.service.app_env = some(env);

    assert_eq!(GatewayConfig::from_args(&args).unwrap().tls, None);
}

#[test]
fn a_certificate_without_a_key_and_a_key_without_a_certificate_are_refused() {
    let mut cert_only = valid_gateway();
    cert_only.tls_cert_file = some("cert.pem");
    let mut key_only = valid_gateway();
    key_only.tls_key_file = some("key.pem");

    assert_eq!(gateway_variables(&cert_only), vec!["GATEWAY_TLS_KEY_FILE"]);
    assert_eq!(gateway_variables(&key_only), vec!["GATEWAY_TLS_CERT_FILE"]);
}

#[test]
fn an_unusable_pair_is_refused_without_reading_it_back() {
    let mut args = valid_gateway();
    args.tls_cert_file = some("/nonexistent/cert.pem");
    args.tls_key_file = some("/nonexistent/key.pem");

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "GATEWAY_TLS_CERT_FILE");
    assert!(
        problems[0]
            .1
            .starts_with("must name a PEM certificate chain"),
        "{problems:?}"
    );
}

#[test]
fn a_usable_pair_is_accepted_in_every_environment() {
    let (cert, key) = certificate_pair("accepted");
    let mut args = valid_gateway();
    args.service.app_env = some("prod");
    args.tls_cert_file = Some(cert.clone());
    args.tls_key_file = Some(key.clone());

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.tls,
        Some(TlsFiles {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
        })
    );
}

#[test]
fn the_gateway_needs_a_key_file_of_the_tokens() {
    let mut args = valid_gateway();
    args.service.tokens.public_keys_file = None;

    assert_eq!(gateway_variables(&args), vec!["JWT_PUBLIC_KEYS_FILE"]);
}

#[test]
fn an_empty_pod_name_and_an_invalid_environment_are_refused() {
    let mut args = valid_gateway();
    args.pod_name = some("");
    args.pod_namespace = some(" ");
    args.service.app_env = some("staging");

    assert_eq!(
        gateway_variables(&args),
        vec!["APP_ENV", "POD_NAME", "POD_NAMESPACE"]
    );
}

#[test]
fn the_maintenance_defaults_are_ten_minutes_and_ninety_days() {
    let config = Config::from_args(valid()).unwrap();

    assert_eq!(config.maintenance.interval, Duration::from_mins(10));
    assert_eq!(
        config.maintenance.orphaned_grant_retention,
        Duration::from_hours(2_160)
    );
}

#[test]
fn the_maintenance_variables_accept_positive_durations() {
    let args = ServeArgs {
        maintenance: MaintenanceArgs {
            interval: some("30s"),
            orphaned_grant_retention: some("30d"),
        },
        ..valid()
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(config.maintenance.interval, Duration::from_secs(30));
    assert_eq!(
        config.maintenance.orphaned_grant_retention,
        Duration::from_hours(720)
    );
}

#[rstest]
#[case("soon", "must be a duration such as 500ms, 2s or 1m")]
#[case("0s", "must be a positive duration such as 10m or 90d")]
fn a_maintenance_interval_that_is_no_positive_duration_names_its_variable(
    #[case] raw: &str,
    #[case] reason: &str,
) {
    let args = ServeArgs {
        maintenance: MaintenanceArgs {
            interval: some(raw),
            ..MaintenanceArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("MAINTENANCE_INTERVAL", reason.to_owned())]
    );
}

#[rstest]
#[case("later", "must be a duration such as 500ms, 2s or 1m")]
#[case("0d", "must be a positive duration such as 10m or 90d")]
fn an_orphaned_grant_retention_that_is_no_positive_duration_names_its_variable(
    #[case] raw: &str,
    #[case] reason: &str,
) {
    let args = ServeArgs {
        maintenance: MaintenanceArgs {
            orphaned_grant_retention: some(raw),
            ..MaintenanceArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("ORPHANED_GRANT_RETENTION", reason.to_owned())]
    );
}

#[test]
fn the_relay_listens_on_the_database_url_by_default_with_a_ten_second_transaction_timeout() {
    let config = Config::from_args(valid()).unwrap();

    assert_eq!(
        config.relay,
        RelaySettings {
            listen_url: "postgres://app:secret@localhost:5432/app".to_owned(),
            transaction_timeout: Duration::from_secs(10),
            publish_wait_timeout: Duration::from_secs(5),
        }
    );
}

#[test]
fn the_relay_variables_accept_a_direct_url_and_a_timeout_from_one_to_ten_seconds() {
    let args = ServeArgs {
        relay: RelayArgs {
            listen_url: some("postgresql://app:secret@db-direct:5432/app"),
            transaction_timeout: some("1s"),
            publish_wait_timeout: some("250ms"),
        },
        ..valid()
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(
        config.relay.listen_url,
        "postgresql://app:secret@db-direct:5432/app"
    );
    assert_eq!(config.relay.transaction_timeout, Duration::from_secs(1));
    assert_eq!(
        config.relay.publish_wait_timeout,
        Duration::from_millis(250)
    );
}

#[test]
fn a_listen_url_that_is_no_postgres_url_names_its_variable() {
    let args = ServeArgs {
        relay: RelayArgs {
            listen_url: some("mysql://app@db/app"),
            ..RelayArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [(
            "DATABASE_LISTEN_URL",
            "must be a postgres:// or postgresql:// URL".to_owned()
        )]
    );
}

#[rstest]
#[case("soon", "must be a duration such as 500ms, 2s or 1m")]
#[case("0s", "must be a duration from 1s to 10s")]
#[case("999ms", "must be a duration from 1s to 10s")]
#[case("11s", "must be a duration from 1s to 10s")]
fn a_transaction_timeout_outside_one_to_ten_seconds_names_its_variable(
    #[case] raw: &str,
    #[case] reason: &str,
) {
    let args = ServeArgs {
        relay: RelayArgs {
            transaction_timeout: some(raw),
            ..RelayArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("KAFKA_TRANSACTION_TIMEOUT", reason.to_owned())]
    );
}

#[test]
fn a_missing_database_url_is_reported_once_and_not_again_for_the_listen_url() {
    let args = ServeArgs {
        database: DatabaseArgs::default(),
        ..valid()
    };

    let reported = problems(args);

    assert_eq!(
        reported
            .iter()
            .filter(|(variable, _)| variable.starts_with("DATABASE_"))
            .count(),
        1
    );
}

#[rstest]
#[case("soon", "must be a duration such as 500ms, 2s or 1m")]
#[case("0s", "must be a duration from 100ms to 30s")]
#[case("99ms", "must be a duration from 100ms to 30s")]
#[case("31s", "must be a duration from 100ms to 30s")]
fn a_publish_wait_timeout_outside_the_accepted_range_names_its_variable(
    #[case] raw: &str,
    #[case] reason: &str,
) {
    let args = ServeArgs {
        relay: RelayArgs {
            publish_wait_timeout: some(raw),
            ..RelayArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        problems(args),
        [("PUBLISH_WAIT_TIMEOUT", reason.to_owned())]
    );
}

#[rstest]
#[case("100ms", Duration::from_millis(100))]
#[case("30s", Duration::from_secs(30))]
fn the_publish_wait_timeout_bounds_are_accepted(#[case] raw: &str, #[case] expected: Duration) {
    let args = ServeArgs {
        relay: RelayArgs {
            publish_wait_timeout: some(raw),
            ..RelayArgs::default()
        },
        ..valid()
    };

    assert_eq!(
        Config::from_args(args).unwrap().relay.publish_wait_timeout,
        expected
    );
}

#[test]
fn the_anti_entropy_defaults_are_five_seconds_and_ten_minutes() {
    let config = Config::from_args(valid()).unwrap();

    assert_eq!(config.anti_entropy.head_interval(), Duration::from_secs(5));
    assert_eq!(config.anti_entropy.full_interval(), Duration::from_mins(10));
}

#[test]
fn the_anti_entropy_variables_accept_positive_durations() {
    let args = ServeArgs {
        anti_entropy: AntiEntropyArgs {
            head_interval: some("2s"),
            full_interval: some("30s"),
        },
        ..valid()
    };

    let config = Config::from_args(args).unwrap();

    assert_eq!(config.anti_entropy.head_interval(), Duration::from_secs(2));
    assert_eq!(config.anti_entropy.full_interval(), Duration::from_secs(30));
}

#[rstest]
#[case("0s")]
#[case("soon")]
fn an_anti_entropy_head_interval_that_is_not_positive_names_its_variable(#[case] raw: &str) {
    let args = ServeArgs {
        anti_entropy: AntiEntropyArgs {
            head_interval: some(raw),
            ..AntiEntropyArgs::default()
        },
        ..valid()
    };

    assert_eq!(variables(args), vec!["ANTI_ENTROPY_HEAD_INTERVAL"]);
}

#[rstest]
#[case("0s")]
#[case("soon")]
fn an_anti_entropy_full_interval_that_is_not_positive_names_its_variable(#[case] raw: &str) {
    let args = ServeArgs {
        anti_entropy: AntiEntropyArgs {
            full_interval: some(raw),
            ..AntiEntropyArgs::default()
        },
        ..valid()
    };

    assert_eq!(variables(args), vec!["ANTI_ENTROPY_FULL_INTERVAL"]);
}

#[test]
fn a_full_interval_shorter_than_the_head_interval_names_the_full_interval() {
    let args = ServeArgs {
        anti_entropy: AntiEntropyArgs {
            head_interval: some("30s"),
            full_interval: some("10s"),
        },
        ..valid()
    };

    assert_eq!(variables(args), vec!["ANTI_ENTROPY_FULL_INTERVAL"]);
}
