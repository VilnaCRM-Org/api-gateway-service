//! The public server of the gateway with connection shedding (Story 15.1, FR-85).
//!
//! NLB deregistration never moves an established connection, so a pod that fails readiness must
//! push its clients to other pods itself. [`serve`] is the accept loop of the public listener:
//! while the shedding flag of the pod is set, an HTTP/2 connection receives `GOAWAY` (hyper's
//! graceful shutdown of the connection, which lets its streams finish) and an HTTP/1.1 response
//! carries `Connection: close`, which ends the connection after it. A connection that arrives
//! while the pod sheds is served; it is told to leave with its first response. When the service
//! stops, every connection is shut down gracefully and the loop returns once they ended.

use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::Extension;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::CONNECTION;
use axum::http::{HeaderValue, Version};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::serve::Listener;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use shared_domain::BoxError;
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;

use super::edge::{Edge, EdgeLimits, proxy};
use super::pipeline::ClientAddress;

/// The two flags that steer the connections of a server.
#[derive(Debug, Clone)]
pub struct ConnectionSignals {
    /// Set when the service stops: no connection is accepted and every one is shut down.
    pub stopping: watch::Receiver<bool>,
    /// Set while the pod is not ready: every connection is told to go to another pod.
    pub shedding: watch::Receiver<bool>,
}

impl ConnectionSignals {
    /// Signals over the stop flag and the shedding flag of the pod; without one, the server never
    /// sheds.
    #[must_use]
    pub fn new(stopping: watch::Receiver<bool>, shedding: Option<watch::Receiver<bool>>) -> Self {
        Self {
            stopping,
            shedding: shedding.unwrap_or_else(|| watch::channel(false).1),
        }
    }
}

/// Whether a connection speaks HTTP/2, learned from its requests, and the wake-up of the task that
/// waits for it.
#[derive(Debug, Default)]
struct Protocol {
    http2: AtomicBool,
    marked: Notify,
}

impl Protocol {
    fn mark_http2(&self) {
        self.http2.store(true, Ordering::Release);
        self.marked.notify_one();
    }

    /// Completes once a request of the connection used HTTP/2.
    async fn is_http2(&self) {
        while !self.http2.load(Ordering::Acquire) {
            self.marked.notified().await;
        }
    }
}

/// What the middleware of a connection reads.
#[derive(Debug, Clone)]
struct ShedState {
    shedding: watch::Receiver<bool>,
    protocol: Arc<Protocol>,
}

/// Records the protocol of the connection and, while the pod sheds, adds `Connection: close` to
/// the responses of HTTP/1.1.
async fn close_on_shed(State(state): State<ShedState>, request: Request, next: Next) -> Response {
    let http2 = request.version() == Version::HTTP_2;
    if http2 {
        state.protocol.mark_http2();
    }
    let mut response = next.run(request).await;
    if !http2 && *state.shedding.borrow() {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Counts the requests of a connection, which the edge reads to retire a connection that carries
/// too many of them.
async fn count_requests(
    State(requests): State<Arc<AtomicU64>>,
    request: Request,
    next: Next,
) -> Response {
    requests.fetch_add(1, Ordering::Relaxed);
    next.run(request).await
}

/// Completes when the stop flag is set or its sender is gone.
async fn stopped(mut stopping: watch::Receiver<bool>) {
    drop(stopping.wait_for(|stopping| *stopping).await);
}

/// Completes when the pod starts to shed; never when its flag is gone.
async fn shed(shedding: &mut watch::Receiver<bool>) {
    if shedding.wait_for(|shedding| *shedding).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Completes when the connection must be shut down gracefully: the service stops, or the pod
/// sheds and the connection speaks HTTP/2. An HTTP/1.1 connection is not shut down at the signal:
/// its next response carries `Connection: close` instead, so no request meets a closed socket.
async fn leave(signals: &mut ConnectionSignals, protocol: &Protocol) {
    tokio::select! {
        () = stopped(signals.stopping.clone()) => {}
        () = async {
            shed(&mut signals.shedding).await;
            protocol.is_http2().await;
        } => {}
    }
}

fn log_ended(result: &Result<(), BoxError>) {
    if let Err(error) = result {
        log_failed(error);
    }
}

fn log_failed(error: &BoxError) {
    tracing::debug!(%error, "a connection ended with an error");
}

/// Serves one connection until it ends, until the service stops, or until the edge retires it: a
/// connection that reached its age, or carries too many requests too fast, is shut down
/// gracefully, which sends `GOAWAY` on HTTP/2 and lets its streams finish.
async fn connection<Io>(io: Io, router: Router, mut signals: ConnectionSignals, edge: &Edge)
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let protocol = Arc::new(Protocol::default());
    let state = ShedState {
        shedding: signals.shedding.clone(),
        protocol: Arc::clone(&protocol),
    };
    let requests = Arc::new(AtomicU64::new(0));
    let router = router
        .layer(middleware::from_fn_with_state(state, close_on_shed))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&requests),
            count_requests,
        ));
    let mut builder = Builder::new(TokioExecutor::new());
    edge.tune(&mut builder);
    let mut served = pin!(
        builder.serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(router))
    );
    tokio::select! {
        result = served.as_mut() => return log_ended(&result),
        () = leave(&mut signals, &protocol) => served.as_mut().graceful_shutdown(),
        () = edge.retire(move || requests.load(Ordering::Relaxed)) => {
            served.as_mut().graceful_shutdown();
        }
    }
    log_ended(&served.await);
}

/// The client address of a connection whose Proxy Protocol header this server reads: the address
/// the header names, or `None` (the connection is closed) when the header is missing or invalid.
async fn resolve_peer<Io>(io: &mut Io, peer: SocketAddr, edge: &Edge) -> Option<SocketAddr>
where
    Io: tokio::io::AsyncRead + Unpin,
{
    if !edge.header_in_serve() {
        return Some(peer);
    }
    match proxy::read_header_within(io, edge.limits().header_read_timeout).await {
        Ok(client) => Some(client.unwrap_or(peer)),
        Err(error) => {
            log_proxy_refused(peer, &error);
            None
        }
    }
}

fn log_proxy_refused(peer: SocketAddr, error: &proxy::ProxyHeaderError) {
    tracing::debug!(%peer, error = %error, "connection without a valid Proxy Protocol header closed");
}

fn log_refused(peer: SocketAddr) {
    tracing::debug!(%peer, "connection refused: the client address holds too many connections");
}

/// Admits one accepted connection and serves it: the Proxy Protocol header is read first when
/// this server reads it, then the client address takes a slot among its connections; at its limit
/// the connection is closed without a byte.
async fn admit_and_serve<Io>(
    mut io: Io,
    peer: SocketAddr,
    router: Router,
    signals: ConnectionSignals,
    edge: Edge,
) where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(peer) = resolve_peer(&mut io, peer, &edge).await else {
        return;
    };
    let Some(_slot) = edge.admit(peer.ip()) else {
        return log_refused(peer);
    };
    let router = router
        .layer(Extension(ClientAddress::from(peer)))
        .layer(Extension(edge.claims()));
    connection(io, router, signals, &edge).await;
}

/// [`serve_with_edge`] over the default limits of the edge, without Proxy Protocol and without
/// jitter of the connection age.
///
/// # Errors
///
/// Never fails: an `accept` that fails is retried by the listener itself.
pub async fn serve<L>(listener: L, router: Router, signals: ConnectionSignals) -> io::Result<()>
where
    L: Listener,
    L::Addr: Into<SocketAddr>,
{
    let edge = Edge::new(EdgeLimits::default(), false, None);
    serve_with_edge(listener, router, signals, edge).await
}

/// Serves `router` on the connections of `listener` within the limits of `edge` (Story 10.9).
///
/// It accepts until the stop flag is set, then waits for the connections to end. Every request
/// carries the address of its client as a [`ClientAddress`] extension, and the subjects its
/// connection claims as an `Arc<SubjectClaims>`.
///
/// # Errors
///
/// Never fails: an `accept` that fails is retried by the listener itself.
pub async fn serve_with_edge<L>(
    mut listener: L,
    router: Router,
    signals: ConnectionSignals,
    edge: Edge,
) -> io::Result<()>
where
    L: Listener,
    L::Addr: Into<SocketAddr>,
{
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = stopped(signals.stopping.clone()) => break,
            (io, address) = listener.accept() => {
                let peer: SocketAddr = address.into();
                connections.spawn(admit_and_serve(
                    io,
                    peer,
                    router.clone(),
                    signals.clone(),
                    edge.clone(),
                ));
            }
        }
        while connections.try_join_next().is_some() {}
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests;
