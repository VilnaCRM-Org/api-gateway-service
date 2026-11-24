use std::net::SocketAddr;
use std::time::Duration;

use test_support::log::LogRecorder;
use tokio::sync::watch;

use super::*;
use crate::bootstrap::TaskMode;

const GRACE: Duration = Duration::from_secs(1);

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn stopped_supervisor() -> (watch::Sender<bool>, TaskSupervisor) {
    let (stop, stopping) = watch::channel(false);
    (stop, TaskSupervisor::new(TaskMode::Test, stopping))
}

#[test]
fn the_runtime_has_workers_and_the_blocking_limit_is_16() {
    let runtime = runtime().unwrap();

    assert!(runtime.metrics().num_workers() >= 1);
    assert_eq!(MAX_BLOCKING_THREADS, 16);
}

#[tokio::test]
async fn bound_sockets_report_their_own_addresses() {
    let sockets = bind_all(&config_on(loopback())).await.unwrap();

    let bound = sockets.addresses().unwrap();

    assert_ne!(bound.public.port(), 0);
    assert_ne!(bound.internal.port(), 0);
    assert_ne!(bound.probe.port(), 0);
    assert_ne!(bound.public, bound.internal);
    assert_ne!(bound.internal, bound.probe);
}

#[tokio::test]
async fn a_taken_address_fails_the_bind() {
    let first = bind(loopback()).await.unwrap();
    let taken = first.local_addr().unwrap();

    assert!(bind(taken).await.is_err());
}

fn config_on(address: SocketAddr) -> GatewayConfig {
    use crate::cli::GatewayArgs;
    use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;

    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    let text = address.to_string();
    args.listen = Some(text.clone());
    args.internal_listen = Some(text.clone());
    args.probe_listen = Some(text);
    GatewayConfig::from_args(&args).unwrap()
}

#[tokio::test]
async fn servers_and_tasks_that_end_in_time_are_a_drained_shutdown() {
    let (stop, tasks) = stopped_supervisor();
    let servers = vec![
        tokio::spawn(async { Ok(()) }),
        tokio::spawn(async { Ok(()) }),
    ];
    stop.send_replace(true);

    assert_eq!(drain(servers, tasks, GRACE).await, Shutdown::Drained);
}

#[tokio::test(start_paused = true)]
async fn a_server_that_outlives_the_grace_period_forces_the_shutdown() {
    let (stop, tasks) = stopped_supervisor();
    let servers = vec![tokio::spawn(std::future::pending())];
    stop.send_replace(true);

    assert_eq!(drain(servers, tasks, GRACE).await, Shutdown::Forced);
}

#[tokio::test(start_paused = true)]
async fn a_task_that_outlives_the_grace_period_forces_the_shutdown() {
    let (stop, mut tasks) = stopped_supervisor();
    tasks.spawn("stubborn", |_shutdown| std::future::pending());
    stop.send_replace(true);

    assert_eq!(
        drain(vec![tokio::spawn(async { Ok(()) })], tasks, GRACE).await,
        Shutdown::Forced
    );
}

#[tokio::test]
async fn a_server_that_fails_while_draining_forces_the_shutdown() {
    let (stop, tasks) = stopped_supervisor();
    let servers = vec![tokio::spawn(async {
        Err(std::io::Error::other("the listener failed"))
    })];
    stop.send_replace(true);

    assert_eq!(drain(servers, tasks, GRACE).await, Shutdown::Forced);
}

#[tokio::test]
async fn the_plain_public_server_answers_503_and_ends_on_the_stop_flag() {
    let (stop, stopping) = watch::channel(false);
    let (_unused, mut tasks) = stopped_supervisor();
    let socket = bind(loopback()).await.unwrap();
    let address = socket.local_addr().unwrap();

    let server = start_public(socket, None, &mut tasks, &stopping).unwrap();
    let answer = raw_get(address).await;
    stop.send_replace(true);

    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.to_lowercase().contains("retry-after: 1"), "{answer}");
    assert!(server.await.unwrap().is_ok());
    assert!(tasks.is_empty());
}

async fn raw_get(address: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[expect(
        clippy::disallowed_methods,
        reason = "the test talks to the listener it started"
    )]
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer
}

#[test]
fn the_listening_and_runtime_entries_name_the_addresses_the_mode_and_the_workers() {
    let config = config_on(loopback());
    let bound = Bound {
        public: SocketAddr::from(([127, 0, 0, 1], 8443)),
        internal: SocketAddr::from(([127, 0, 0, 1], 8444)),
        probe: SocketAddr::from(([127, 0, 0, 1], 8445)),
    };
    let runtime = runtime().unwrap();

    let (recorder, guard) = LogRecorder::install();
    log_listening(&config, &bound);
    log_runtime(&runtime);
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].message, "listening");
    let field = |name: &str| {
        lines[0]
            .fields
            .iter()
            .find(|(key, _value)| key == name)
            .map(|(_key, value)| value.clone())
    };
    assert_eq!(field("public_addr").as_deref(), Some("127.0.0.1:8443"));
    assert_eq!(field("tls").as_deref(), Some("false"));
    assert_eq!(field("env").as_deref(), Some("test"));
    assert_eq!(field("pod").as_deref(), Some(""));
    assert_eq!(field("namespace").as_deref(), Some(""));
    assert_eq!(lines[1].message, "runtime started");
    assert!(
        lines[1]
            .fields
            .iter()
            .any(|(key, value)| key == "max_blocking_threads" && value == "16"),
        "{:?}",
        lines[1].fields
    );
}

#[tokio::test]
async fn a_death_notice_of_the_apply_thread_completes_the_wait() {
    let (notice, death) = oneshot::channel();
    notice.send(()).unwrap();

    tokio::time::timeout(GRACE, apply_thread_died(death))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_apply_thread_that_ended_cleanly_never_completes_the_wait() {
    let (notice, death) = oneshot::channel::<()>();
    drop(notice);

    let waited = tokio::time::timeout(Duration::from_millis(50), apply_thread_died(death)).await;

    assert!(waited.is_err());
}
