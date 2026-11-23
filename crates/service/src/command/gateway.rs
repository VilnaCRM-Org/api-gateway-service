//! `service gateway`: binds the public, internal and probe listeners, serves until SIGTERM or
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
use shared_domain::BoxError;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::serve::{
    FORCED_EXIT_LIMIT, Shutdown, Signals, log_forced, log_signal, log_stopped, mode, stopped,
};
use crate::bootstrap::gateway::listener::{self, ReloadableCertificate, TlsListener};
use crate::bootstrap::gateway::{self, GatewayAdapters, internal, probe};
use crate::bootstrap::{TaskStop, TaskSupervisor};
use crate::config::{GatewayConfig, TlsFiles};
use crate::telemetry;

/// The most threads the runtime lends to blocking calls.
pub const MAX_BLOCKING_THREADS: usize = 16;

/// A running listener.
type Server = JoinHandle<std::io::Result<()>>;

/// The three bound sockets of the gateway.
struct Sockets {
    public: TcpListener,
    internal: TcpListener,
    probe: TcpListener,
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
        internal: bind(config.internal_listen).await?,
        probe: bind(config.probe_listen).await?,
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

/// Starts the public server: over TLS with the certificate watcher when the files are
/// configured, over plain HTTP otherwise (the configuration allows that only in `dev` and `test`).
fn start_public(
    socket: TcpListener,
    tls: Option<&TlsFiles>,
    tasks: &mut TaskSupervisor,
    stopping: &watch::Receiver<bool>,
) -> Result<Server, BoxError> {
    let router = listener::stale_router();
    let Some(files) = tls else {
        return Ok(spawn_server(socket, router, stopping.clone()));
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
    let secured = TlsListener::new(socket, listener::server_config(resolver)?)?;
    Ok(spawn_server(secured, router, stopping.clone()))
}

fn start_servers(
    config: &GatewayConfig,
    sockets: Sockets,
    tasks: &mut TaskSupervisor,
    stopping: &watch::Receiver<bool>,
) -> Result<Vec<Server>, BoxError> {
    let public = start_public(sockets.public, config.tls.as_ref(), tasks, stopping)?;
    let internal = spawn_server(sockets.internal, internal::router(), stopping.clone());
    let probe = spawn_server(sockets.probe, probe::router(), stopping.clone());
    Ok(vec![public, internal, probe])
}

/// The addresses the sockets are bound to.
struct Bound {
    public: SocketAddr,
    internal: SocketAddr,
    probe: SocketAddr,
}

impl Sockets {
    fn addresses(&self) -> std::io::Result<Bound> {
        Ok(Bound {
            public: self.public.local_addr()?,
            internal: self.internal.local_addr()?,
            probe: self.probe.local_addr()?,
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
        internal_addr = %bound.internal,
        probe_addr = %bound.probe,
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

/// Wires the adapters, binds, serves and drains.
async fn gateway(config: &GatewayConfig) -> Result<Shutdown, BoxError> {
    let signals = Signals::install()?;
    let adapters = GatewayAdapters::from_config(config)?;
    let (stop, stopping) = watch::channel(false);
    let mut tasks = gateway::start_tasks(&adapters, stopping.clone());
    let sockets = bind_all(config).await?;
    let bound = sockets.addresses()?;
    let servers = start_servers(config, sockets, &mut tasks, &stopping)?;
    log_listening(config, &bound);
    log_signal(signals.received().await);
    stop.send_replace(true);
    Ok(drain(servers, tasks, config.shutdown_grace_period).await)
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
