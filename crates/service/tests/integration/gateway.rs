//! `service gateway` as a process: its listeners, TLS, certificate reload, runtime and shutdown.

use std::io::Read as _;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use test_support::tls::{CertificateFiles, self_signed};
use tokio::time::Instant;

use crate::support::{
    DEAD_DATABASE_URL, GatewayPorts, Scratch, Server, gateway, get_on, stderr, stdout,
};

/// A gateway on plain HTTP in `APP_ENV` `test`.
fn plain(scratch: &Scratch, extra: &[(&str, &str)]) -> (Server, GatewayPorts) {
    gateway(scratch, extra)
}

/// A gateway that serves TLS with `pair`.
fn secured(
    scratch: &Scratch,
    pair: &CertificateFiles,
    extra: &[(&str, &str)],
) -> (Server, GatewayPorts) {
    let cert = pair.cert.to_str().unwrap();
    let key = pair.key.to_str().unwrap();
    let mut variables = vec![
        ("GATEWAY_TLS_CERT_FILE", cert),
        ("GATEWAY_TLS_KEY_FILE", key),
    ];
    variables.extend_from_slice(extra);
    gateway(scratch, &variables)
}

/// One TLS handshake with `openssl s_client`; the text is what the client printed.
fn handshake(port: u16, flags: &[&str]) -> (Output, String) {
    let output = Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-servername", "localhost"])
        .args(flags)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = format!("{}{}", stdout(&output), stderr(&output));
    (output, text)
}

/// Waits until a handshake shows `needle`, for at most 15 seconds, and returns what it printed.
fn handshake_until(port: u16, needle: &str) -> String {
    let started = Instant::now();
    loop {
        let (_output, text) = handshake(port, &[]);
        if text.contains(needle) {
            return text;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no handshake showed {needle}: {text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn the_public_listener_negotiates_tls_13_and_12_with_alpn_and_refuses_tls_11() {
    let scratch = Scratch::new();
    let pair = self_signed(scratch.path(), "gateway", "first");
    let (server, ports) = secured(&scratch, &pair, &[]);

    let (_output, tls13) = handshake(ports.public, &["-tls1_3", "-alpn", "h2"]);
    let (_output, tls12) = handshake(ports.public, &["-tls1_2", "-alpn", "http/1.1"]);
    let (output, tls11) = handshake(ports.public, &["-tls1_1", "-cipher", "ALL:@SECLEVEL=0"]);
    let finished = server.terminate();

    assert!(tls13.contains("TLSv1.3"), "{tls13}");
    assert!(tls13.contains("ALPN protocol: h2"), "{tls13}");
    assert!(tls12.contains("TLSv1.2"), "{tls12}");
    assert!(tls12.contains("ALPN protocol: http/1.1"), "{tls12}");
    assert!(!output.status.success(), "{tls11}");
    // openssl prints the offered version in its session block even when the server refuses: the
    // refusal is the handshake alert and the absence of a negotiated cipher.
    assert!(tls11.contains("Cipher is (NONE)"), "{tls11}");
    assert!(tls11.contains("alert handshake failure"), "{tls11}");
    assert_eq!(finished.code, Some(0));
}

#[test]
fn a_replaced_certificate_is_presented_and_a_broken_one_keeps_the_last_valid_pair() {
    let scratch = Scratch::new();
    let live = self_signed(scratch.path(), "gateway", "first");
    let next = self_signed(scratch.path(), "next", "second");
    let (mut server, ports) = secured(&scratch, &live, &[]);
    let first = handshake_until(ports.public, "CN=first");

    std::fs::copy(&next.key, &live.key).unwrap();
    std::fs::copy(&next.cert, &live.cert).unwrap();
    let second = handshake_until(ports.public, "CN=second");
    server.read_until("gateway certificate reloaded");
    std::fs::write(&live.cert, "no longer a certificate").unwrap();
    let failure =
        server.read_until("gateway certificate reload failed, the last valid pair stays in force");
    let (_output, after) = handshake(ports.public, &[]);
    let finished = server.terminate();

    assert!(first.contains("CN=first"), "{first}");
    assert!(second.contains("CN=second"), "{second}");
    assert_eq!(failure.last().unwrap()["level"], "ERROR");
    assert!(after.contains("CN=second"), "{after}");
    assert_eq!(finished.code, Some(0));
}

#[test]
fn without_a_snapshot_the_public_listener_answers_503_iam_stale_and_ping_answers_200() {
    let scratch = Scratch::new();
    let (server, ports) = plain(&scratch, &[]);

    let public = server.get("/api/users");
    let post = server.request("POST", "/api/roles", &[], "{}");
    let ping = get_on(ports.probe, "/ping");
    let public_ping = server.get("/ping");
    let internal = get_on(ports.internal, "/internal/freshness");
    let unknown_probe = get_on(ports.probe, "/nothing");
    let finished = server.terminate();

    assert_eq!(public.status, 503);
    assert!(public.head.contains("retry-after: 1"), "{}", public.head);
    assert!(
        public
            .head
            .contains("content-type: application/problem+json"),
        "{}",
        public.head
    );
    assert!(
        public.body.contains("/problems/iam_stale"),
        "{}",
        public.body
    );
    assert_eq!(post.status, 503);
    assert_eq!(ping.status, 200);
    assert_eq!(ping.body, "pong");
    assert_eq!(public_ping.status, 503);
    assert_eq!(internal.status, 404);
    assert_eq!(unknown_probe.status, 404);
    assert_eq!(finished.code, Some(0));
}

#[test]
fn the_gateway_starts_without_a_database_and_never_connects_to_one() {
    let scratch = Scratch::new();
    let (unset, ports) = plain(&scratch, &[]);
    let unset_ping = get_on(ports.probe, "/ping").status;
    let unset_end = unset.terminate();
    let (dead, dead_ports) = plain(&scratch, &[("DATABASE_URL", DEAD_DATABASE_URL)]);
    let dead_ping = get_on(dead_ports.probe, "/ping").status;
    let dead_end = dead.terminate();

    assert_eq!(unset_ping, 200);
    assert_eq!(dead_ping, 200);
    for finished in [&unset_end, &dead_end] {
        assert_eq!(finished.code, Some(0));
        let messages = finished.messages();
        assert!(
            !messages.iter().any(|message| message.contains("database")),
            "{messages:?}"
        );
        assert_eq!(finished.stderr, "");
    }
}

#[test]
fn the_runtime_reports_the_configured_worker_threads_and_16_blocking_threads() {
    let scratch = Scratch::new();
    let (server, _ports) = plain(&scratch, &[("TOKIO_WORKER_THREADS", "2")]);

    let finished = server.terminate();

    let started = finished
        .lines
        .iter()
        .find(|line| line["message"] == "runtime started")
        .unwrap();
    assert_eq!(started["workers"], 2);
    assert_eq!(started["max_blocking_threads"], 16);
}

#[test]
fn an_idle_gateway_stops_on_sigterm_within_the_grace_period_with_exit_status_0() {
    let scratch = Scratch::new();
    let (server, _ports) = plain(&scratch, &[("SHUTDOWN_GRACE_PERIOD", "3s")]);
    let started = Instant::now();

    let finished = server.terminate();

    assert_eq!(finished.code, Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    // The bootstrap meets no broker here, so its own entries are left out.
    assert_eq!(
        finished.lifecycle_messages(),
        [
            "runtime started",
            "listening",
            "shutdown signal received",
            "stopped"
        ]
    );
    assert_eq!(finished.stderr, "");
}

#[test]
fn a_connection_open_at_the_end_of_the_grace_period_forces_exit_status_1() {
    let scratch = Scratch::new();
    let (mut server, _ports) = plain(&scratch, &[("SHUTDOWN_GRACE_PERIOD", "1s")]);
    let mut stream = server.begin("/");
    assert_eq!(server.get("/").status, 503);
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
    assert!(!finished.messages().contains(&"stopped"));
    assert!(read.is_err() || rest.is_empty(), "{rest}");
}

#[test]
fn an_invalid_gateway_configuration_is_reported_as_log_entries_with_exit_status_2() {
    let scratch = Scratch::new();

    let output = scratch.run(
        &["gateway"],
        &[
            ("APP_ENV", "test"),
            ("GATEWAY_LISTEN", "127.0.0.1:9100"),
            ("GATEWAY_INTERNAL_LISTEN", "127.0.0.1:9100"),
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    let log = stdout(&output);
    assert!(
        log.contains("\"variable\":\"GATEWAY_INTERNAL_LISTEN\""),
        "{log}"
    );
    assert!(log.contains("invalid configuration"), "{log}");
}

#[test]
fn a_taken_listener_address_is_one_failure_entry_with_exit_status_1() {
    let scratch = Scratch::new();
    let (first, ports) = plain(&scratch, &[]);
    let taken = format!("127.0.0.1:{}", ports.public);

    let output = scratch.run(
        &["gateway"],
        &[
            ("APP_ENV", "test"),
            ("GATEWAY_LISTEN", taken.as_str()),
            ("GATEWAY_INTERNAL_LISTEN", "127.0.0.1:0"),
            ("GATEWAY_PROBE_LISTEN", "127.0.0.1:0"),
        ],
    );
    drop(first.terminate());

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("gateway failed"),
        "{}",
        stdout(&output)
    );
}
