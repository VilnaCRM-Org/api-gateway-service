//! `service gateway`: binds the public, east-west, internal, decision and probe listeners, serves until SIGTERM or
//! SIGINT and drains (ADR 0015).
//!
//! The data plane needs no database: nothing here opens a PostgreSQL pool. Every line it writes is
//! one JSON log entry on standard output (NFR31).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::serve::Listener;
use iam_application::{
    AppliedPoll, AppliedPollSettings, EndpointReadyPeers, OpenStreams, PodProbes,
    ReadYourWritesBarrier, StreamReauthorizer,
};
use iam_domain::{PolicyView, ReadyPeers};
use rustls::ServerConfig;
use shared_domain::{BoxError, Clock};
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use super::serve::{
    FORCED_EXIT_LIMIT, Shutdown, Signals, log_forced, log_signal, log_stopped, mode, stopped,
};
use crate::bootstrap::gateway::decision::{self, DecisionPorts};
use crate::bootstrap::gateway::edge::{Edge, EdgeLimits};
use crate::bootstrap::gateway::endpoints;
use crate::bootstrap::gateway::graphql_ws::SocketSettings;
use crate::bootstrap::gateway::listener::{self, ReloadableCertificate, TlsListener};
use crate::bootstrap::gateway::shedding::{self, ConnectionSignals};
use crate::bootstrap::gateway::streams::{PodFence, StreamFence, StreamSettings, Streams};
use crate::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use crate::bootstrap::gateway::{self, GatewayAdapters, internal, pipeline, policy, probe};
use crate::bootstrap::{TaskStop, TaskSupervisor};
use crate::config::{GatewayConfig, TlsFiles};
use crate::telemetry;

/// The most threads the runtime lends to blocking calls.
pub const MAX_BLOCKING_THREADS: usize = 16;

/// A running listener.
type Server = JoinHandle<std::io::Result<()>>;

/// The five bound sockets of the gateway.
struct Sockets {
    public: TcpListener,
    mesh: TcpListener,
    internal: TcpListener,
    probe: TcpListener,
    decision: TcpListener,
}

/// The multi-thread runtime of the gateway. Tokio reads `TOKIO_WORKER_THREADS` itself, so the
/// worker count is the variable or the number of cores; blocking calls are capped at
/// [`MAX_BLOCKING_THREADS`].
///
/// # Errors
///
/// Returns the error of starting the runtime.
pub fn runtime() -> std::io::Result<Runtime> {
    Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
}

#[expect(
    clippy::disallowed_methods,
    reason = "the gateway command owns its listening sockets"
)]
async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

async fn bind_all(config: &GatewayConfig) -> std::io::Result<Sockets> {
    Ok(Sockets {
        public: bind(config.listen).await?,
        mesh: bind(config.mesh_listen).await?,
        internal: bind(config.internal_listen).await?,
        probe: bind(config.probe_listen).await?,
        decision: bind(config.decision_listen).await?,
    })
}

fn spawn_server<L>(listener: L, router: Router, stopping: watch::Receiver<bool>) -> Server
where
    L: Listener,
    L::Addr: std::fmt::Debug,
{
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(stopped(stopping))
            .await
    })
}

/// Serves the public listener with connection shedding: while the pod is not ready, its HTTP/2
/// connections receive `GOAWAY` and its HTTP/1.1 responses `Connection: close` (Story 15.1).
fn spawn_shedding_server<L>(listener: L, router: Router, signals: ConnectionSignals) -> Server
where
    L: Listener,
    L::Addr: Into<SocketAddr>,
{
    tokio::spawn(shedding::serve(listener, router, signals))
}

/// The TLS configuration of the proxy listeners, with the watcher that replaces the certificate
/// without a restart; `None` serves plain HTTP, which the configuration allows only in `dev` and
/// `test`. The public and the east-west listener share it, so they present the same certificate.
fn tls_config(
    tls: Option<&TlsFiles>,
    tasks: &mut TaskSupervisor,
) -> Result<Option<Arc<ServerConfig>>, BoxError> {
    let Some(files) = tls else {
        return Ok(None);
    };
    let (key, loaded) = listener::load_with_source(files)?;
    let resolver = Arc::new(ReloadableCertificate::new(key));
    let watched = (Arc::clone(&resolver), files.clone());
    tasks.spawn("gateway-certificate", move |shutdown| {
        listener::watch_files(
            watched.0,
            watched.1,
            loaded,
            listener::RELOAD_INTERVAL,
            shutdown,
        )
    });
    Ok(Some(listener::server_config(resolver)?))
}

/// Starts a proxy server on `socket`: over TLS with `config` when there is one, over plain HTTP
/// otherwise. The accept loop reads no Proxy Protocol header: the client address is the TCP peer.
fn start_proxy(
    socket: TcpListener,
    config: Option<Arc<ServerConfig>>,
    router: Router,
    signals: ConnectionSignals,
) -> Result<Server, BoxError> {
    match config {
        Some(config) => Ok(spawn_shedding_server(
            TlsListener::new(socket, config)?,
            router,
            signals,
        )),
        None => Ok(spawn_shedding_server(socket, router, signals)),
    }
}

/// Starts the public server behind the limits of `edge` (Story 10.9): over TLS with `config` when
/// there is one, over plain HTTP otherwise. With `GATEWAY_PROXY_PROTOCOL`, every connection starts
/// with a Proxy Protocol v2 header, read before the TLS handshake, and one without it is closed.
fn start_edge_proxy(
    socket: TcpListener,
    config: Option<Arc<ServerConfig>>,
    router: Router,
    signals: ConnectionSignals,
    edge: Edge,
) -> Result<Server, BoxError> {
    let edge = edge.reading_header_in_serve(config.is_none());
    match config {
        Some(config) => {
            let secured = TlsListener::with_edge(socket, config, edge.clone())?;
            let served = shedding::serve_with_edge(secured, router, signals, edge);
            Ok(tokio::spawn(served))
        }
        None => Ok(tokio::spawn(shedding::serve_with_edge(
            socket, router, signals, edge,
        ))),
    }
}

/// The edge of the public listener: the limits of the story, the connection age jittered through
/// the `Rng` port, and the Proxy Protocol of `GATEWAY_PROXY_PROTOCOL`.
fn public_edge(config: &GatewayConfig, adapters: &GatewayAdapters) -> Edge {
    Edge::standard(config.proxy_protocol, Arc::clone(&adapters.rng))
}

/// The collaborators the public pipeline is wired with besides the configuration and the clock.
struct PublicPorts {
    forwarder: Arc<pipeline::Forwarder>,
    access_log: Arc<pipeline::PipelineAccessLog>,
    peers: Arc<dyn ReadyPeers>,
    streams: Arc<Streams>,
}

/// The routers of the two proxy listeners: with a freshness state they are the request pipeline
/// that hands authorized requests to `forwarder`, without one every request is answered 503
/// `iam_stale`. The east-west router runs the same pipeline and route table as the public one; its
/// only difference is the caller rule for `ROLE_SERVICE` tokens (Story 10.13).
///
/// # Errors
///
/// The error of wiring the pipeline, such as an unreadable key file.
fn proxy_routers(
    config: &GatewayConfig,
    policy: &policy::PolicyAdapters,
    clock: &Arc<dyn Clock>,
    ports: PublicPorts,
) -> Result<ProxyRouters, BoxError> {
    let Some(freshness) = policy.freshness.as_ref() else {
        return Ok(ProxyRouters {
            public: listener::stale_router(),
            mesh: listener::stale_router(),
        });
    };
    let view: Arc<dyn PolicyView> =
        Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
    let state = Arc::clone(&freshness.state);
    let pipeline = pipeline::from_config(config, view, state, clock, ports.forwarder)?;
    let pipeline = pipeline
        .with_read_your_writes(read_your_writes_barrier(config, policy))
        .with_rate_limits(pipeline::gate_from_config(config, ports.peers))
        .with_access_log(ports.access_log)
        .with_streams(ports.streams)
        .with_graphql_ws(SocketSettings {
            init_timeout: config.graphql_ws_init_timeout,
        });
    let mesh = pipeline
        .clone()
        .with_service_callers(config.tokens.callers.clone());
    Ok(ProxyRouters {
        public: pipeline::router(pipeline),
        mesh: pipeline::router(mesh),
    })
}

/// The router of each proxy listener.
struct ProxyRouters {
    public: Router,
    mesh: Router,
}

/// The read-your-writes barrier of the pod (Story 10.10): over the published snapshot and the
/// versions the apply thread announces, waiting at most `RYW_MAX_WAIT`.
fn read_your_writes_barrier(
    config: &GatewayConfig,
    policy: &policy::PolicyAdapters,
) -> Arc<ReadYourWritesBarrier> {
    let view: Arc<dyn PolicyView> =
        Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
    Arc::new(ReadYourWritesBarrier::new(
        view,
        Arc::clone(&policy.versions),
        config.ryw_max_wait,
    ))
}

/// The router of the internal listener: with a freshness state it serves `/internal/freshness`,
/// and it serves `/internal/policy/applied` from process start (Story 13.3).
fn internal_router(config: &GatewayConfig, policy: &policy::PolicyAdapters) -> Router {
    let base = policy
        .freshness
        .as_ref()
        .map_or_else(internal::router, |freshness| {
            let view: Arc<dyn PolicyView> =
                Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
            internal::router_with_freshness(Arc::clone(&freshness.state), view)
        });
    internal::with_applied(base, applied_poll(config, policy))
}

/// The pod's answer to the Sync-Fence coordinator.
///
/// It reads the published version, the finished re-evaluations of the open streams and the `HW0`
/// that the bootstrap captured.
fn applied_poll(config: &GatewayConfig, policy: &policy::PolicyAdapters) -> Arc<AppliedPoll> {
    Arc::new(AppliedPoll::new(
        Arc::clone(&policy.versions),
        Arc::clone(&policy.reevaluation),
        Arc::clone(&policy.high_water),
        AppliedPollSettings {
            pod: config
                .pod_name
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            hard_bound: config.freshness_hard_bound,
            max_concurrent: config.applied_poll_max_concurrent,
        },
    ))
}

/// The router of the decision listener: with a freshness state it serves the decision API from the
/// snapshot, without one only the 404 problem.
///
/// # Errors
///
/// The error of setting the decision API up, such as an unreadable key file.
fn decision_router(
    config: &GatewayConfig,
    policy: &policy::PolicyAdapters,
    clock: Arc<dyn Clock>,
) -> Result<Router, BoxError> {
    let Some(freshness) = policy.freshness.as_ref() else {
        return Ok(internal::router());
    };
    let view: Arc<dyn PolicyView> =
        Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
    let ports = DecisionPorts {
        view,
        freshness: Arc::clone(&freshness.state),
        clock,
    };
    let barrier = read_your_writes_barrier(config, policy);
    Ok(decision::router_with_barrier(config, ports, &barrier)?)
}

/// The router of the probe listener: with a freshness state it serves the three probes of the pod
/// (Story 9.7), without one only `/ping`.
fn probe_router(policy: &policy::PolicyAdapters) -> Router {
    policy
        .freshness
        .as_ref()
        .map_or_else(probe::router, |freshness| {
            let view: Arc<dyn PolicyView> =
                Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
            let probes = PodProbes::new(
                Arc::clone(&policy.status),
                Arc::clone(&freshness.state),
                view,
            );
            let probes = match policy.readiness.as_ref() {
                Some(readiness) => probes.with_peer_readiness(Arc::clone(&readiness.gate)),
                None => probes,
            };
            probe::router_with_probes(Arc::new(probes))
        })
}

/// Starts the scan of the stream registry (Story 11.1): it closes the streams of a pod that
/// fenced or whose proof is not fresh, and those whose token, idle time or assignments ran out.
/// Without a freshness state the pod serves no request, so it holds no stream either.
fn spawn_stream_watch(
    tasks: &mut TaskSupervisor,
    streams: &Arc<Streams>,
    policy: &policy::PolicyAdapters,
) {
    let Some(freshness) = policy.freshness.as_ref() else {
        return;
    };
    let view: Arc<dyn PolicyView> =
        Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
    let fence: Arc<dyn StreamFence> = Arc::new(PodFence::new(view, Arc::clone(&freshness.state)));
    let streams = Arc::clone(streams);
    tasks.spawn("gateway-streams", move |shutdown| {
        streams.watch(fence, shutdown)
    });
}

/// Starts the re-authorization of the open streams (Story 11.2): it takes each publication of the
/// apply thread off its board and decides again only the streams that publication touched, so
/// the apply thread never waits for it and the record of finished re-evaluations moves up in
/// order.
fn spawn_stream_reauthorizer(
    tasks: &mut TaskSupervisor,
    streams: &Arc<Streams>,
    policy: &policy::PolicyAdapters,
) {
    let view: Arc<dyn PolicyView> =
        Arc::<iam_infrastructure::ArcSwapPolicySnapshot>::clone(&policy.cell);
    let open: Arc<dyn OpenStreams> = Arc::<Streams>::clone(streams);
    let reauthorizer = Arc::new(StreamReauthorizer::new(
        open,
        view,
        Arc::clone(&policy.reevaluation),
    ));
    tasks.spawn(StreamReauthorizer::name(), |shutdown| {
        reauthorizer.run(shutdown)
    });
}

fn start_servers(
    config: &GatewayConfig,
    sockets: Sockets,
    adapters: &GatewayAdapters,
    tasks: &mut TaskSupervisor,
    stopping: &watch::Receiver<bool>,
) -> Result<Vec<Server>, BoxError> {
    let policy = &adapters.policy;
    let forwarder = HyperUpstreamForwarder::new(
        adapters.endpoints.directory.view(),
        config.endpoints.zone_aware,
        Arc::clone(&adapters.rng),
    );
    let access_log = adapters.access_log.pipeline_step(&adapters.clock);
    let forwarder = Arc::new(forwarder);
    let peers: Arc<dyn ReadyPeers> = Arc::new(EndpointReadyPeers::new(
        adapters.endpoints.directory.view(),
        endpoints::peers_target(config),
    ));
    let streams = Streams::new(
        StreamSettings {
            idle_timeout: config.stream_idle_timeout,
            per_subject: EdgeLimits::default().connections_per_subject,
        },
        Arc::clone(&adapters.clock),
    );
    spawn_stream_watch(tasks, &streams, policy);
    spawn_stream_reauthorizer(tasks, &streams, policy);
    let ports = PublicPorts {
        forwarder,
        access_log,
        peers,
        streams,
    };
    let ProxyRouters {
        public: public_router,
        mesh: mesh_router,
    } = proxy_routers(config, policy, &adapters.clock, ports)?;
    let internal_router = internal_router(config, policy);
    let decision_router = decision_router(config, policy, Arc::clone(&adapters.clock))?;
    let tls = tls_config(config.tls.as_ref(), tasks)?;
    let signals = ConnectionSignals::new(
        stopping.clone(),
        policy
            .readiness
            .as_ref()
            .map(|readiness| readiness.gate.shedding()),
    );
    let mesh = start_proxy(sockets.mesh, tls.clone(), mesh_router, signals.clone())?;
    let edge = public_edge(config, adapters);
    let public = start_edge_proxy(sockets.public, tls, public_router, signals, edge)?;
    let internal = spawn_server(sockets.internal, internal_router, stopping.clone());
    let probe = spawn_server(sockets.probe, probe_router(policy), stopping.clone());
    let decision = spawn_server(sockets.decision, decision_router, stopping.clone());
    Ok(vec![public, mesh, internal, probe, decision])
}

/// The addresses the sockets are bound to.
struct Bound {
    public: SocketAddr,
    mesh: SocketAddr,
    internal: SocketAddr,
    probe: SocketAddr,
    decision: SocketAddr,
}

impl Sockets {
    fn addresses(&self) -> std::io::Result<Bound> {
        Ok(Bound {
            public: self.public.local_addr()?,
            mesh: self.mesh.local_addr()?,
            internal: self.internal.local_addr()?,
            probe: self.probe.local_addr()?,
            decision: self.decision.local_addr()?,
        })
    }
}

/// The values are computed before the macro: an expression inside the field list is evaluated
/// only when the event is enabled, so it stays out of the coverage of the binaries that do not log.
fn log_listening(config: &GatewayConfig, bound: &Bound) {
    let tls = config.tls.is_some();
    let env = mode(config.app_env);
    let pod = config.pod_name.as_deref().unwrap_or_default();
    let namespace = config.pod_namespace.as_deref().unwrap_or_default();
    tracing::info!(
        public_addr = %bound.public,
        mesh_addr = %bound.mesh,
        internal_addr = %bound.internal,
        probe_addr = %bound.probe,
        decision_addr = %bound.decision,
        tls,
        env,
        pod,
        namespace,
        version = env!("CARGO_PKG_VERSION"),
        "listening"
    );
}

fn log_runtime(runtime: &Runtime) {
    let workers = runtime.metrics().num_workers();
    tracing::info!(
        workers,
        max_blocking_threads = MAX_BLOCKING_THREADS,
        "runtime started"
    );
}

fn log_failed(error: &BoxError) {
    tracing::error!(error = %error, "gateway failed");
}

/// Waits for the servers and for the tasks within the grace period; the stop flag is set.
async fn drain(servers: Vec<Server>, tasks: TaskSupervisor, grace_period: Duration) -> Shutdown {
    let servers = async {
        let mut drained = true;
        for server in servers {
            drained &= matches!(server.await, Ok(Ok(())));
        }
        drained
    };
    let (servers_end, tasks_end) = tokio::join!(
        tokio::time::timeout(grace_period, servers),
        tasks.stop(grace_period)
    );
    if servers_end == Ok(true) && tasks_end == TaskStop::Drained {
        log_stopped();
        Shutdown::Drained
    } else {
        log_forced(grace_period);
        Shutdown::Forced
    }
}

/// The apply thread or the policy tail ended without being asked to: the pod cannot follow the
/// policy log any more.
#[derive(Debug, thiserror::Error)]
#[error("the apply thread or the policy tail died")]
struct ApplyThreadDied;

/// Completes when the apply thread dies; a thread that ends cleanly never completes it.
async fn apply_thread_died(death: oneshot::Receiver<()>) {
    if death.await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Wires the adapters, binds, serves and drains. A dead apply thread ends the gateway with a
/// failure once the servers drained.
async fn gateway(config: &GatewayConfig) -> Result<Shutdown, BoxError> {
    let signals = Signals::install()?;
    let adapters = GatewayAdapters::from_config(config)?;
    let (stop, stopping) = watch::channel(false);
    let mut tasks = gateway::start_tasks(&adapters, stopping.clone());
    let death = policy::start_policy(&adapters.policy, &mut tasks)?;
    let sockets = bind_all(config).await?;
    let bound = sockets.addresses()?;
    let servers = start_servers(config, sockets, &adapters, &mut tasks, &stopping)?;
    log_listening(config, &bound);
    let outcome = tokio::select! {
        received = signals.received() => {
            log_signal(received);
            Ok(())
        }
        () = apply_thread_died(death) => Err(ApplyThreadDied),
    };
    stop.send_replace(true);
    let shutdown = drain(servers, tasks, config.shutdown_grace_period).await;
    adapters.access_log.finish();
    outcome.map(|()| shutdown).map_err(BoxError::from)
}

fn start(config: &GatewayConfig) -> Result<Shutdown, BoxError> {
    telemetry::init(&config.log_level, std::io::stdout)?;
    let runtime = runtime()?;
    log_runtime(&runtime);
    let outcome = runtime.block_on(gateway(config));
    // Connections that are still open are dropped here, within a bounded time.
    runtime.shutdown_timeout(FORCED_EXIT_LIMIT);
    outcome
}

/// Serves until a signal arrives: 0 when every request finished, 1 when the grace period ended
/// with a connection open or the gateway failed (an entry `gateway failed` says why).
#[must_use]
pub fn run(config: &GatewayConfig) -> ExitCode {
    match start(config) {
        Ok(Shutdown::Drained) => ExitCode::SUCCESS,
        Ok(Shutdown::Forced) => ExitCode::FAILURE,
        Err(error) => {
            log_failed(&error);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
