//! `service healthcheck` against a running service and against a port nothing listens on.

use sqlx::PgPool;

use crate::support::{Scratch, Server, database_url, serve, silent_listener, stack_with};

/// A running service on the database of `pool`, with `extra` variables after the stack's own.
async fn serve_on(scratch: &Scratch, pool: &PgPool, extra: &[(&str, &str)]) -> Server {
    let url = database_url(pool).await;
    let owned = stack_with(&url);
    let mut variables: Vec<(&str, &str)> = owned
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    variables.extend_from_slice(extra);
    serve(scratch, &variables)
}

fn exit_code(scratch: &Scratch, arguments: &[&str], port: &str) -> Option<i32> {
    scratch.run(arguments, &[("APP_PORT", port)]).status.code()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn succeeds_against_a_running_service_and_fails_with_nothing_listening(pool: PgPool) {
    let scratch = Scratch::new();
    let server = serve_on(&scratch, &pool, &[]).await;
    let port = server.port.to_string();
    let alive = exit_code(&scratch, &["healthcheck"], &port);
    let flag = scratch
        .run(&["healthcheck", "--port", &port], &[])
        .status
        .code();
    let finished = server.terminate();
    let dead = exit_code(&scratch, &["healthcheck"], &port);

    assert_eq!(alive, Some(0));
    assert_eq!(flag, Some(0));
    assert_eq!(finished.code, Some(0));
    assert_eq!(dead, Some(1));
}

#[test]
fn an_unparsable_port_and_a_listener_that_never_answers_fail() {
    let scratch = Scratch::new();
    let listener = silent_listener();
    let port = listener.local_addr().unwrap().port().to_string();
    let started = tokio::time::Instant::now();

    let unparsable = exit_code(&scratch, &["healthcheck"], "not-a-port");
    let silent = exit_code(&scratch, &["healthcheck"], &port);

    assert_eq!(unparsable, Some(1));
    assert_eq!(silent, Some(1));
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn prints_nothing() {
    let scratch = Scratch::new();

    let output = scratch.run(&["healthcheck"], &[("APP_PORT", "1")]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert_eq!(output.stderr, Vec::<u8>::new());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn probes_the_address_the_service_listens_on(pool: PgPool) {
    let scratch = Scratch::new();
    let server = serve_on(&scratch, &pool, &[("APP_HOST", "127.0.0.2")]).await;
    let port = server.port.to_string();
    let with_host = |host: &str| {
        scratch
            .run(
                &["healthcheck"],
                &[("APP_PORT", port.as_str()), ("APP_HOST", host)],
            )
            .status
            .code()
    };

    let bound = with_host("127.0.0.2");
    let loopback = with_host("127.0.0.1");
    let unspecified = with_host("0.0.0.0");
    let invalid = with_host("not-an-address");
    let flag = scratch
        .run(
            &["healthcheck", "--port", &port, "--host", "127.0.0.2"],
            &[],
        )
        .status
        .code();
    let finished = server.terminate();

    assert_eq!(bound, Some(0));
    assert_eq!(flag, Some(0));
    assert_eq!(loopback, Some(1));
    assert_eq!(unspecified, Some(1));
    assert_eq!(invalid, Some(1));
    assert_eq!(finished.code, Some(0));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_unspecified_listener_is_probed_on_the_loopback_interface(pool: PgPool) {
    let scratch = Scratch::new();
    let server = serve_on(&scratch, &pool, &[("APP_HOST", "0.0.0.0")]).await;
    let port = server.port.to_string();

    let alive = scratch
        .run(
            &["healthcheck"],
            &[("APP_PORT", port.as_str()), ("APP_HOST", "0.0.0.0")],
        )
        .status
        .code();
    let finished = server.terminate();

    assert_eq!(alive, Some(0));
    assert_eq!(finished.code, Some(0));
}
