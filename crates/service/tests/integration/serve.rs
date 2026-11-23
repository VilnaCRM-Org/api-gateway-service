//! `service serve` as a process: start-up, the request log, shutdown, failures and outages.

use std::io::{Read as _, Write as _};
use std::time::Duration;

use serde_json::Value;
use sqlx::{AssertSqlSafe, Connection as _, PgPool};
use tokio::time::Instant;

use crate::support::{
    DEAD_DATABASE_URL, Scratch, Server, VALID_ENVIRONMENT, database_url, serve, stack_with,
};

const REQUEST_ID: &str = "serve-test-1";

/// The configuration of a service whose dependencies do not answer.
const DEAD_DEPENDENCIES: [(&str, &str); 3] = [
    ("DATABASE_URL", DEAD_DATABASE_URL),
    ("AWS_REGION", "us-east-1"),
    ("AWS_ENDPOINT_URL_SQS", "http://127.0.0.1:1"),
];

/// Messages written outside a request.
const OUTSIDE_REQUESTS: [&str; 3] = ["listening", "shutdown signal received", "stopped"];

/// The message of a record that the start-up registration of IAM's own specifications appends to
/// the security audit log, which a fresh database receives before the service listens.
const AUDIT_EVENT: &str = "security audit event";

/// The entries of the service itself: every entry but the security audit records.
fn service_entries(lines: &[Value]) -> Vec<&Value> {
    lines
        .iter()
        .filter(|line| line["message"] != AUDIT_EVENT)
        .collect()
}

fn messages(entries: &[&Value]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| entry["message"].as_str().unwrap().to_owned())
        .collect()
}

/// A running service on the database of `pool`, which registers IAM's own specifications before
/// it listens.
async fn live_server(scratch: &Scratch, pool: &PgPool, extra: &[(&str, &str)]) -> Server {
    let url = database_url(pool).await;
    let owned = stack_with(&url);
    let mut variables = as_pairs(&owned);
    variables.extend_from_slice(extra);
    serve(scratch, &variables)
}

fn as_pairs<'a>(owned: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    owned
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

fn messages_of<'a>(lines: &'a [Value], message: &str) -> Vec<&'a Value> {
    lines
        .iter()
        .filter(|line| line["message"] == message)
        .collect()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_request_sequence_is_logged_as_json_with_the_request_id(pool: PgPool) {
    let scratch = Scratch::new();
    let url = database_url(&pool).await;
    let owned = stack_with(&url);
    let server = serve(&scratch, &as_pairs(&owned));
    let headers = [
        ("x-request-id", REQUEST_ID),
        ("content-type", "application/json"),
    ];
    let body = r#"{"name":"Serve test","description":"Created through the spawned binary"}"#;

    let ping = server.request("GET", "/ping", &headers, "");
    let health = server.request("GET", "/api/health", &headers, "");
    let created = server.request("POST", "/api/example_api_resources", &headers, body);
    let unknown = server.request("GET", "/no-such-route", &headers, "");
    let finished = server.terminate();

    assert_eq!((ping.status, ping.body.as_str()), (200, "pong"));
    assert_eq!(health.status, 204);
    assert!(
        ping.head.contains("x-request-id: serve-test-1"),
        "{}",
        ping.head
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(unknown.status, 404);
    assert_eq!(finished.code, Some(0));
    assert_eq!(finished.stderr, "");
    let entries = service_entries(&finished.lines);
    let listening = entries[0];
    assert_eq!(listening["message"], "listening");
    assert_eq!(listening["level"], "INFO");
    assert!(
        listening["addr"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    assert_eq!(listening["env"], "test");
    assert_eq!(listening["version"], env!("CARGO_PKG_VERSION"));
    for line in &finished.lines {
        for key in ["timestamp", "level", "message"] {
            assert!(line[key].is_string(), "{key} missing in {line}");
        }
    }
    let inside: Vec<&Value> = entries
        .iter()
        .copied()
        .filter(|line| !OUTSIDE_REQUESTS.contains(&line["message"].as_str().unwrap()))
        .collect();
    assert!(
        inside
            .iter()
            .all(|line| line["span"]["request_id"] == REQUEST_ID),
        "{inside:?}"
    );
    assert_eq!(messages_of(&finished.lines, "request completed").len(), 4);
    assert_eq!(messages_of(&finished.lines, "domain event").len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_start_up_entry_names_the_mode(pool: PgPool) {
    for mode in ["dev", "test", "prod"] {
        let scratch = Scratch::new();
        // `prod` refuses the PLAINTEXT listener and the relaxed gates of the compose broker; the
        // connection is lazy, so the secured settings need no reachable cluster to start.
        let secured = [
            ("APP_ENV", mode),
            ("KAFKA_SECURITY_PROTOCOL", "SASL_SSL"),
            ("KAFKA_CONFIG_GATES", "enforce"),
        ];
        let extra = if mode == "prod" {
            &secured[..]
        } else {
            &secured[..1]
        };
        let server = live_server(&scratch, &pool, extra).await;

        let finished = server.terminate();

        assert_eq!(service_entries(&finished.lines)[0]["env"], mode);
        assert_eq!(finished.code, Some(0));
    }
}

/// Returns when the service has accepted the connection opened by `begin` and handed it to its
/// task. A service accepts connections in the order they were made, so an answered request on a
/// later connection proves that the earlier one was accepted. It does not prove that the task of
/// the earlier connection has already been polled.
fn wait_until_accepted(server: &Server) {
    assert_eq!(server.get("/ping").status, 200);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_idle_service_stops_on_sigterm_within_two_seconds(pool: PgPool) {
    let scratch = Scratch::new();
    let server = live_server(&scratch, &pool, &[]).await;
    let started = Instant::now();

    let finished = server.terminate();

    assert_eq!(finished.code, Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    let entries = service_entries(&finished.lines);
    assert_eq!(
        messages(&entries),
        ["listening", "shutdown signal received", "stopped"]
    );
    assert_eq!(entries[1]["signal"], "SIGTERM");
    assert_eq!(entries[1]["level"], "INFO");
    assert_eq!(entries[2]["level"], "INFO");
    assert_eq!(finished.stderr, "");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn sigint_stops_the_service_like_sigterm(pool: PgPool) {
    let scratch = Scratch::new();
    let server = live_server(&scratch, &pool, &[]).await;

    server.signal("INT");
    let finished = server.finish();

    assert_eq!(finished.code, Some(0));
    let entries = service_entries(&finished.lines);
    assert_eq!(entries[1]["signal"], "SIGINT");
    assert_eq!(entries[2]["message"], "stopped");
    assert_eq!(entries[1]["level"], "INFO");
    assert_eq!(entries[2]["level"], "INFO");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_request_in_flight_completes_and_new_connections_are_refused(pool: PgPool) {
    let scratch = Scratch::new();
    let mut server = live_server(&scratch, &pool, &[]).await;
    let mut stream = server.begin("/ping");
    wait_until_accepted(&server);

    server.signal("TERM");
    server.read_until("shutdown signal received");
    server.wait_until_refusing(Duration::from_secs(10));
    stream.write_all(b"\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let finished = server.finish();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("pong"), "{response}");
    assert_eq!(finished.code, Some(0));
    assert_eq!(finished.lines.last().unwrap()["message"], "stopped");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_connection_open_at_the_end_of_the_grace_period_forces_exit_status_1(pool: PgPool) {
    let scratch = Scratch::new();
    let mut server = live_server(&scratch, &pool, &[("SHUTDOWN_GRACE_PERIOD", "1s")]).await;
    let mut stream = server.begin("/ping");
    wait_until_accepted(&server);
    let started = Instant::now();

    server.signal("TERM");
    server.read_until("shutdown signal received");
    let finished = server.finish();
    let elapsed = started.elapsed();
    let mut rest = String::new();
    let read = stream.read_to_string(&mut rest);

    assert_eq!(finished.code, Some(1));
    assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    let last = finished.lines.last().unwrap();
    assert_eq!(last["message"], "grace period elapsed, forcing shutdown");
    assert_eq!(last["level"], "WARN");
    assert_eq!(last["grace_period"], "1s");
    assert!(!finished.messages().contains(&"stopped"));
    assert!(
        read.is_err() || rest.is_empty(),
        "the connection was answered: {rest}"
    );
    assert_eq!(finished.stderr, "");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_port_in_use_is_one_serve_failed_entry_and_exit_status_1(pool: PgPool) {
    let scratch = Scratch::new();
    let first = live_server(&scratch, &pool, &[]).await;
    let port = first.port.to_string();
    let url = database_url(&pool).await;
    let owned = stack_with(&url);
    let mut variables = as_pairs(&owned);
    variables.extend([("APP_PORT", port.as_str()), ("APP_HOST", "127.0.0.1")]);

    let second = scratch.run(&["serve"], &variables);
    let first = first.terminate();

    assert_eq!(second.status.code(), Some(1));
    assert_eq!(crate::support::stderr(&second), "");
    let stdout = crate::support::stdout(&second);
    let lines: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    assert_eq!(lines[0]["message"], "serve failed");
    assert_eq!(lines[0]["level"], "ERROR");
    assert!(
        lines[0]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    assert_eq!(first.code, Some(0));
}

#[test]
fn an_invalid_variable_is_one_json_entry_per_problem_and_exit_status_2() {
    let scratch = Scratch::new();
    let variables = [
        ("APP_PORT", "eighty"),
        ("DATABASE_URL", "mysql://root:hunter2@db/app"),
    ];

    let output = scratch.run(&["serve"], &variables);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(crate::support::stderr(&output), "");
    let stdout = crate::support::stdout(&output);
    let lines: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let named: Vec<&str> = lines
        .iter()
        .map(|line| line["variable"].as_str().unwrap())
        .collect();
    assert_eq!(named, ["APP_PORT", "DATABASE_URL", "AWS_REGION"]);
    for line in &lines {
        assert_eq!(line["message"], "invalid configuration");
        assert_eq!(line["level"], "ERROR");
        assert!(
            line["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }
    assert!(!stdout.contains("hunter2"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_unreachable_message_broker_does_not_stop_ping_and_health_names_it(pool: PgPool) {
    let scratch = Scratch::new();
    let started = Instant::now();
    let server = live_server(
        &scratch,
        &pool,
        &[("AWS_ENDPOINT_URL_SQS", "http://127.0.0.1:1")],
    )
    .await;

    let ping = server.get("/ping");
    let ping_after = started.elapsed();
    let probed = Instant::now();
    let health = server.get("/api/health");
    let probe_took = probed.elapsed();
    let finished = server.terminate();

    assert_eq!(ping.status, 200);
    assert!(ping_after < Duration::from_secs(5), "{ping_after:?}");
    assert_eq!(health.status, 500);
    assert!(probe_took < Duration::from_secs(4), "{probe_took:?}");
    assert!(!health.body.contains("Database"), "{}", health.body);
    assert!(health.body.contains("Message broker"), "{}", health.body);
    assert!(!health.body.contains("Cache"), "{}", health.body);
    assert_eq!(finished.code, Some(0));
}

#[test]
fn the_database_url_and_credentials_are_never_logged() {
    let scratch = Scratch::new();
    let mut variables = VALID_ENVIRONMENT.to_vec();
    variables.push(("AWS_ENDPOINT_URL_SQS", "http://127.0.0.1:1"));
    variables[0] = ("DATABASE_URL", "postgres://app:s3cret-pass@127.0.0.1:1/app");

    let output = scratch.run(&["serve"], &variables);

    let text = format!(
        "{}{}",
        crate::support::stdout(&output),
        crate::support::stderr(&output)
    );
    assert_ne!(text, "");
    assert!(!text.contains("s3cret-pass"), "{text}");
}

#[test]
fn an_unreachable_database_fails_the_start_with_one_serve_failed_entry() {
    let scratch = Scratch::new();

    let output = scratch.run(&["serve"], &DEAD_DEPENDENCIES);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(crate::support::stderr(&output), "");
    let stdout = crate::support::stdout(&output);
    let lines: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    assert_eq!(lines[0]["message"], "serve failed");
    assert!(
        !stdout.contains("listening"),
        "the service listened before IAM's specifications were registered: {stdout}"
    );
}

#[sqlx::test(migrations = false)]
async fn serve_applies_no_migration_and_fails_on_a_database_that_was_never_migrated(pool: PgPool) {
    let scratch = Scratch::new();
    let url = database_url(&pool).await;
    let owned = stack_with(&url);

    let output = scratch.run(&["serve"], &as_pairs(&owned));

    assert_eq!(output.status.code(), Some(1));
    assert!(
        crate::support::stdout(&output).contains("serve failed"),
        "{}",
        crate::support::stdout(&output)
    );
    for table in ["example_api_resources", "_sqlx_migrations"] {
        let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(found, None, "{table}");
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn entries_inside_nested_spans_carry_the_request_id(pool: PgPool) {
    let scratch = Scratch::new();
    let url = database_url(&pool).await;
    let mut owned = stack_with(&url);
    // The Kafka client writes its connection entries from tasks of its own, outside any span of
    // the service; only the service's entries are this test's subject.
    owned.push(("LOG_LEVEL", "debug,krafka=warn".to_owned()));
    let server = serve(&scratch, &as_pairs(&owned));

    let health = server.request("GET", "/api/health", &[("x-request-id", REQUEST_ID)], "");
    let finished = server.terminate();

    assert_eq!(health.status, 204, "{}", health.body);
    assert_eq!(finished.code, Some(0));
    // The one request is the only work between the start-up marker and the signal; entries of
    // start-up (the AWS configuration is read in spans of its own) come before the marker.
    let listening = finished
        .lines
        .iter()
        .position(|line| line["message"] == "listening");
    let signal = finished
        .lines
        .iter()
        .position(|line| line["message"] == "shutdown signal received");
    let inside = &finished.lines[listening.unwrap().saturating_add(1)..signal.unwrap()];
    assert!(
        inside
            .iter()
            .any(|line| line["span"]["name"] != "http.request"),
        "no entry was written inside a nested span: {inside:?}"
    );
    for line in inside {
        assert_eq!(line["spans"][0]["name"], "http.request", "{line}");
        assert_eq!(line["spans"][0]["request_id"], REQUEST_ID, "{line}");
    }
}

/// Asks `/api/health` until it answers 204 or `limit` has passed, and returns the last answer.
fn health_within(server: &Server, limit: Duration) -> crate::support::Answer {
    let started = Instant::now();
    loop {
        let answer = server.get("/api/health");
        if answer.status == 204 || started.elapsed() >= limit {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[sqlx::test(migrations = false)]
async fn health_recovers_without_a_restart_when_the_database_comes_back(pool: PgPool) {
    let scratch = Scratch::new();
    let current = database_url(&pool).await;
    let (server_url, name) = current.rsplit_once('/').unwrap();
    // A name of the same length as the unique one the test server gave this test (PostgreSQL
    // truncates names to 63 bytes), derived from it and never from input.
    let outage = name.replacen("_sqlx_test_", "_recovered_", 1);
    assert_ne!(outage, name);
    let outage_url = format!("{server_url}/{outage}");
    // The name is the same in every run, so a run that was interrupted between the creation and
    // the removal below would leave a database that makes every later run fail at the creation.
    sqlx::query(AssertSqlSafe(format!(
        r#"DROP DATABASE IF EXISTS "{outage}" WITH (FORCE)"#
    )))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(AssertSqlSafe(format!(r#"CREATE DATABASE "{outage}""#)))
        .execute(&pool)
        .await
        .unwrap();
    let mut connection = sqlx::PgConnection::connect(&outage_url).await.unwrap();
    shared_infrastructure::persistence::MIGRATOR
        .run(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    let mut owned = stack_with(&outage_url);
    let acquire_timeout = Duration::from_secs(30);
    owned.retain(|(variable, _)| *variable != "DATABASE_ACQUIRE_TIMEOUT");
    owned.push((
        "DATABASE_ACQUIRE_TIMEOUT",
        format!("{}s", acquire_timeout.as_secs()),
    ));
    let server = serve(&scratch, &as_pairs(&owned));
    assert_eq!(health_within(&server, acquire_timeout).status, 204);

    // The database goes away while the service runs, and comes back empty.
    sqlx::query(AssertSqlSafe(format!(
        r#"DROP DATABASE "{outage}" WITH (FORCE)"#
    )))
    .execute(&pool)
    .await
    .unwrap();
    let down = server.get("/api/health");
    sqlx::query(AssertSqlSafe(format!(r#"CREATE DATABASE "{outage}""#)))
        .execute(&pool)
        .await
        .unwrap();
    let recovered = health_within(
        &server,
        acquire_timeout.saturating_add(Duration::from_secs(1)),
    );
    let finished = server.terminate();
    sqlx::query(AssertSqlSafe(format!(
        r#"DROP DATABASE "{outage}" WITH (FORCE)"#
    )))
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(down.status, 500, "{}", down.body);
    let problem: Value = serde_json::from_str(&down.body).unwrap();
    assert_eq!(problem["detail"], "Database is not available", "{problem}");
    assert_eq!(recovered.status, 204, "{}", recovered.body);
    assert_eq!(finished.code, Some(0));
}
