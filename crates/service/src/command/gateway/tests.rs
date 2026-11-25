use std::net::SocketAddr;
use std::time::Duration;

use test_support::log::LogRecorder;
use tokio::sync::watch;

use super::*;
use crate::bootstrap::TaskMode;
use crate::bootstrap::gateway::access_log::AccessLogAdapters;

const GRACE: Duration = Duration::from_secs(1);

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn streams_over(clock: &Arc<dyn Clock>) -> Arc<Streams> {
    Streams::new(
        StreamSettings {
            idle_timeout: Duration::from_mins(5),
            per_subject: 32,
        },
        Arc::clone(clock),
    )
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
    assert_ne!(bound.decision.port(), 0);
    assert_ne!(bound.mesh.port(), 0);
    assert_ne!(bound.public, bound.internal);
    assert_ne!(bound.internal, bound.probe);
    assert_ne!(bound.probe, bound.decision);
    assert_ne!(bound.decision, bound.mesh);
    assert_ne!(bound.mesh, bound.public);
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
    args.decision_listen = Some(text.clone());
    args.mesh_listen = Some(text.clone());
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

    let router = listener::stale_router();
    let signals = ConnectionSignals::new(stopping, None);
    let config = tls_config(None, &mut tasks).unwrap();
    let server = start_proxy(socket, config, router, signals).unwrap();
    let answer = raw_get(address).await;
    stop.send_replace(true);

    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.to_lowercase().contains("retry-after: 1"), "{answer}");
    assert!(server.await.unwrap().is_ok());
    assert!(tasks.is_empty());
}

/// An access log step over a writer that is stopped at once: the tests below read no record.
fn access_log_step(clock: &Arc<dyn Clock>) -> Arc<pipeline::PipelineAccessLog> {
    let adapters = AccessLogAdapters::start(
        &crate::config::AccessLogSettings::default(),
        Arc::new(test_support::rng::FakeRng::seeded(1)),
        Arc::clone(clock),
        Arc::new(test_support::access_log_sink::RecordingAccessLogSink::new()),
    )
    .unwrap();
    let step = adapters.pipeline_step(clock);
    adapters.finish();
    step
}

#[tokio::test]
async fn a_gateway_without_a_freshness_state_wires_the_stale_router_and_the_bare_internal_router() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use test_support::boot_clock::FakeBootClock;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use tower::ServiceExt as _;

    let policy = policy::PolicyAdapters::with(
        Arc::new(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::new(FakeBootClock::new()),
    );
    let clock: Arc<dyn Clock> = Arc::new(shared_infrastructure::clock::SystemClock);

    let routers = proxy_routers(
        &config_on(loopback()),
        &policy,
        &clock,
        PublicPorts {
            forwarder: Arc::new(pipeline::UnreachableUpstreams),
            access_log: access_log_step(&clock),
            peers: Arc::new(test_support::ready_peers::FakeReadyPeers::new(1)),
            streams: streams_over(&clock),
        },
    )
    .unwrap();
    let _internal = internal_router(&policy);
    let answer = routers
        .public
        .oneshot(Request::get("/anything").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let mesh_answer = routers
        .mesh
        .oneshot(Request::get("/anything").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert!(policy.freshness.is_none());
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mesh_answer.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_gateway_with_a_freshness_state_serves_the_freshness_endpoint_and_the_pipeline_gates_the_public_listener()
 {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use iam_application::FreshnessState;
    use iam_domain::FreshnessRule;
    use test_support::boot_clock::FakeBootClock;
    use test_support::peer_freshness_client::FakePeerFreshnessClient;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use test_support::policy_log_probe::FakePolicyLogProbe;
    use tower::ServiceExt as _;

    use crate::bootstrap::gateway::freshness::FreshnessAdapters;

    let clock = Arc::new(FakeBootClock::new());
    let freshness = FreshnessAdapters {
        state: Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&clock),
        )),
        probe: Arc::new(FakePolicyLogProbe::scripted(Vec::new())),
        peers: Arc::new(FakePeerFreshnessClient::new()),
        clock: Arc::<FakeBootClock>::clone(&clock),
        probe_interval: Duration::from_secs(1),
    };
    let policy =
        policy::PolicyAdapters::with(Arc::new(FakePolicyBootstrapLog::with(Vec::new())), clock)
            .proving(freshness);

    let clock: Arc<dyn Clock> = Arc::new(shared_infrastructure::clock::SystemClock);
    let routers = proxy_routers(
        &config_on(loopback()),
        &policy,
        &clock,
        PublicPorts {
            forwarder: Arc::new(pipeline::UnreachableUpstreams),
            access_log: access_log_step(&clock),
            peers: Arc::new(test_support::ready_peers::FakeReadyPeers::new(1)),
            streams: streams_over(&clock),
        },
    )
    .unwrap();
    let internal = internal_router(&policy);
    let gated = routers
        .public
        .oneshot(Request::get("/anything").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let mesh_gated = routers
        .mesh
        .oneshot(Request::get("/anything").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let report = internal
        .oneshot(
            Request::get("/internal/freshness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(gated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mesh_gated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(report.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_gateway_without_a_freshness_state_serves_only_ping_on_the_probe_listener() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use test_support::boot_clock::FakeBootClock;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use tower::ServiceExt as _;

    let policy = policy::PolicyAdapters::with(
        Arc::new(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::new(FakeBootClock::new()),
    );

    let ping = probe_router(&policy)
        .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let ready = probe_router(&policy)
        .oneshot(Request::get("/internal/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(ping.status(), StatusCode::OK);
    assert_eq!(ready.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_gateway_without_a_freshness_state_serves_only_the_404_problem_on_the_decision_listener()
{
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use shared_infrastructure::clock::SystemClock;
    use test_support::boot_clock::FakeBootClock;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use tower::ServiceExt as _;

    let policy = policy::PolicyAdapters::with(
        Arc::new(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::new(FakeBootClock::new()),
    );
    let router = decision_router(&config_on(loopback()), &policy, Arc::new(SystemClock)).unwrap();

    let answer = router
        .oneshot(
            Request::post("/api/access-validations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(answer.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_gateway_with_a_freshness_state_serves_the_three_probes_over_the_status_of_its_policy() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use iam_application::FreshnessState;
    use iam_domain::FreshnessRule;
    use test_support::boot_clock::FakeBootClock;
    use test_support::peer_freshness_client::FakePeerFreshnessClient;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use test_support::policy_log_probe::FakePolicyLogProbe;
    use tower::ServiceExt as _;

    use crate::bootstrap::gateway::freshness::FreshnessAdapters;

    let clock = Arc::new(FakeBootClock::new());
    let freshness = FreshnessAdapters {
        state: Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&clock),
        )),
        probe: Arc::new(FakePolicyLogProbe::scripted(Vec::new())),
        peers: Arc::new(FakePeerFreshnessClient::new()),
        clock: Arc::<FakeBootClock>::clone(&clock),
        probe_interval: Duration::from_secs(1),
    };
    let policy =
        policy::PolicyAdapters::with(Arc::new(FakePolicyBootstrapLog::with(Vec::new())), clock)
            .proving(freshness);

    let mut statuses = Vec::new();
    for path in ["/ping", "/internal/startup", "/internal/ready"] {
        let response = probe_router(&policy)
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        statuses.push(response.status());
    }

    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE
        ]
    );

    let decision = decision_router(
        &config_on(loopback()),
        &policy,
        Arc::new(shared_infrastructure::clock::SystemClock),
    )
    .unwrap()
    .oneshot(
        Request::post("/api/access-validations")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"credential":"x","service":"orders","permissions":["rest:orders:GET /api/orders"],"requestId":"r1"}"#,
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(decision.status(), StatusCode::OK);
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
        mesh: SocketAddr::from(([127, 0, 0, 1], 8447)),
        internal: SocketAddr::from(([127, 0, 0, 1], 8444)),
        probe: SocketAddr::from(([127, 0, 0, 1], 8445)),
        decision: SocketAddr::from(([127, 0, 0, 1], 8446)),
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
    assert_eq!(field("mesh_addr").as_deref(), Some("127.0.0.1:8447"));
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

#[tokio::test]
async fn a_gateway_with_peer_readiness_serves_the_probes_over_the_gate_of_the_comparison() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use iam_application::{EndpointDirectory, FreshnessState, ZoneSource};
    use iam_domain::{FreshnessRule, WatchTarget};
    use test_support::boot_clock::FakeBootClock;
    use test_support::peer_freshness_client::FakePeerFreshnessClient;
    use test_support::peer_freshness_reader::FakePeerFreshnessReader;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use test_support::policy_log_probe::FakePolicyLogProbe;
    use test_support::rng::FakeRng;
    use tower::ServiceExt as _;

    use crate::bootstrap::gateway::freshness::FreshnessAdapters;
    use crate::bootstrap::gateway::readiness::ReadinessAdapters;

    let clock = Arc::new(FakeBootClock::new());
    let freshness = FreshnessAdapters {
        state: Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&clock),
        )),
        probe: Arc::new(FakePolicyLogProbe::scripted(Vec::new())),
        peers: Arc::new(FakePeerFreshnessClient::new()),
        clock: Arc::<FakeBootClock>::clone(&clock),
        probe_interval: Duration::from_secs(1),
    };
    let peers = WatchTarget {
        namespace: "iam".to_owned(),
        service: "iam-gateway-peers".to_owned(),
    };
    let directory = EndpointDirectory::new(ZoneSource {
        peers: peers.clone(),
        pod: None,
        explicit: None,
    });
    let readiness = ReadinessAdapters::with(
        &config_on(loopback()),
        &directory,
        peers,
        Arc::new(FakePeerFreshnessReader::new()),
        Arc::new(FakeRng::seeded(1)),
    );
    let policy =
        policy::PolicyAdapters::with(Arc::new(FakePolicyBootstrapLog::with(Vec::new())), clock)
            .proving(freshness)
            .comparing(readiness);

    let ready = probe_router(&policy)
        .oneshot(Request::get("/internal/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_stream_scan_starts_only_on_a_pod_with_a_freshness_state() {
    use iam_application::FreshnessState;
    use iam_domain::FreshnessRule;
    use test_support::boot_clock::FakeBootClock;
    use test_support::peer_freshness_client::FakePeerFreshnessClient;
    use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;
    use test_support::policy_log_probe::FakePolicyLogProbe;

    use crate::bootstrap::gateway::freshness::FreshnessAdapters;

    let clock: Arc<dyn Clock> = Arc::new(shared_infrastructure::clock::SystemClock);
    let streams = streams_over(&clock);
    let boot = Arc::new(FakeBootClock::new());
    let bare = policy::PolicyAdapters::with(
        Arc::new(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::<FakeBootClock>::clone(&boot),
    );
    let proving = policy::PolicyAdapters::with(
        Arc::new(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::<FakeBootClock>::clone(&boot),
    )
    .proving(FreshnessAdapters {
        state: Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&boot),
        )),
        probe: Arc::new(FakePolicyLogProbe::scripted(Vec::new())),
        peers: Arc::new(FakePeerFreshnessClient::new()),
        clock: boot,
        probe_interval: Duration::from_secs(1),
    });
    let (stop, mut tasks) = stopped_supervisor();

    spawn_stream_watch(&mut tasks, &streams, &bare);
    assert!(tasks.is_empty());
    spawn_stream_watch(&mut tasks, &streams, &proving);

    assert_eq!(tasks.len(), 1);
    stop.send_replace(true);
    assert_eq!(tasks.stop(GRACE).await, TaskStop::Drained);
}
