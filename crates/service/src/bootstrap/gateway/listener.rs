//! The public listener of the gateway: rustls with TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`,
//! and a certificate that is replaced without a restart (FR-45, FR-67).
//!
//! The certificate lives in an [`ArcSwap`] behind a certificate resolver, so a handshake takes
//! whichever pair is current when it starts. [`watch_files`] polls the two files and replaces the
//! pair when their content changed and parses; a pair that does not parse is logged and the last
//! valid one stays in force. Until the pipeline of Story 10.2 exists, the public router answers
//! every request with 503 `iam_stale`, because no snapshot is published.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::State;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::serve::Listener;
use iam_application::FreshnessState;
use iam_domain::PolicyView;
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use shared_application::http::Problem;
use shared_application::http::fallback::not_found;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::config::TlsFiles;

/// How often the certificate files are compared with the pair in force.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// How long a client may take to finish the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failed `accept`, such as running out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Handshakes that are done and wait for the server to take them.
const COMPLETED_HANDSHAKES: usize = 128;

/// `type` of the problem of a gateway without a published snapshot.
pub const TYPE_IAM_STALE: &str = "/problems/iam_stale";

/// Why a certificate pair could not be used. No message contains key material.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// A file cannot be read.
    #[error("the {file} cannot be read: {source}")]
    Read {
        /// `certificate chain` or `private key`.
        file: &'static str,
        /// What the operating system reported.
        source: io::Error,
    },
    /// A file is not PEM of the expected kind.
    #[error("the {file} is not valid PEM: {source}")]
    Pem {
        /// `certificate chain` or `private key`.
        file: &'static str,
        /// What the PEM decoder reported.
        source: rustls_pki_types::pem::Error,
    },
    /// The certificate file holds no certificate.
    #[error("the certificate chain holds no certificate")]
    NoCertificate,
    /// The key is not usable or does not belong to the certificate.
    #[error("the private key cannot be used with the certificate chain: {0}")]
    Key(#[from] rustls::Error),
}

/// The bytes of the certificate and key files, as they were read.
#[derive(Clone, PartialEq, Eq)]
pub struct PemPair {
    cert: Vec<u8>,
    key: Vec<u8>,
}

impl std::fmt::Debug for PemPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PemPair").finish_non_exhaustive()
    }
}

fn read_pair(files: &TlsFiles) -> Result<PemPair, CertificateError> {
    let read = |path: &std::path::Path, file| {
        std::fs::read(path).map_err(|source| CertificateError::Read { file, source })
    };
    Ok(PemPair {
        cert: read(&files.cert, "certificate chain")?,
        key: read(&files.key, "private key")?,
    })
}

fn parse_pair(pair: &PemPair) -> Result<CertifiedKey, CertificateError> {
    let chain = CertificateDer::pem_slice_iter(&pair.cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CertificateError::Pem {
            file: "certificate chain",
            source,
        })?;
    if chain.is_empty() {
        return Err(CertificateError::NoCertificate);
    }
    let key = PrivateKeyDer::from_pem_slice(&pair.key).map_err(|source| CertificateError::Pem {
        file: "private key",
        source,
    })?;
    let certified = CertifiedKey::new(chain, any_supported_type(&key)?);
    certified.keys_match()?;
    Ok(certified)
}

/// Reads and parses the pair, and returns the bytes that [`watch_files`] compares later.
///
/// # Errors
///
/// Returns why a file cannot be read, is not PEM, holds no certificate, or holds a key that does
/// not match the certificate.
pub fn load_with_source(files: &TlsFiles) -> Result<(CertifiedKey, PemPair), CertificateError> {
    let pair = read_pair(files)?;
    let key = parse_pair(&pair)?;
    Ok((key, pair))
}

/// Reads and parses the pair.
///
/// # Errors
///
/// The errors of [`load_with_source`].
pub fn load_certified_key(files: &TlsFiles) -> Result<CertifiedKey, CertificateError> {
    load_with_source(files).map(|(key, _pair)| key)
}

/// The certificate resolver: it hands every handshake the pair in force.
#[derive(Debug)]
pub struct ReloadableCertificate {
    current: ArcSwap<CertifiedKey>,
}

impl ReloadableCertificate {
    /// A resolver that presents `key` until it is replaced.
    #[must_use]
    pub fn new(key: CertifiedKey) -> Self {
        Self {
            current: ArcSwap::from_pointee(key),
        }
    }

    /// Makes `key` the pair of every handshake that starts from now on.
    pub fn replace(&self, key: CertifiedKey) {
        self.current.store(Arc::new(key));
    }

    /// The pair in force.
    #[must_use]
    pub fn current(&self) -> Arc<CertifiedKey> {
        self.current.load_full()
    }
}

impl ResolvesServerCert for ReloadableCertificate {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// The TLS configuration of the public listener: TLS 1.3 and 1.2 only, ALPN `h2` and `http/1.1`,
/// no client certificate.
///
/// # Errors
///
/// Returns the error of rustls when the provider supports none of the versions.
pub fn server_config(
    resolver: Arc<ReloadableCertificate>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// What one look at the files found.
enum Checked {
    Unchanged,
    Replaced(CertifiedKey, Arc<PemPair>),
    Rejected(CertificateError, Arc<PemPair>),
    Unreadable(CertificateError),
}

fn check(files: &TlsFiles, current: &PemPair) -> Checked {
    let pair = match read_pair(files) {
        Ok(pair) if pair == *current => return Checked::Unchanged,
        Ok(pair) => Arc::new(pair),
        Err(error) => return Checked::Unreadable(error),
    };
    match parse_pair(&pair) {
        Ok(key) => Checked::Replaced(key, pair),
        Err(error) => Checked::Rejected(error, pair),
    }
}

fn apply(
    resolver: &ReloadableCertificate,
    current: Arc<PemPair>,
    checked: Checked,
) -> Arc<PemPair> {
    match checked {
        Checked::Unchanged => current,
        Checked::Replaced(key, pair) => {
            resolver.replace(key);
            log_reloaded();
            pair
        }
        Checked::Rejected(error, pair) => {
            log_rejected(&error);
            pair
        }
        Checked::Unreadable(error) => {
            log_rejected(&error);
            current
        }
    }
}

async fn reload(
    resolver: &ReloadableCertificate,
    files: &TlsFiles,
    current: Arc<PemPair>,
) -> Arc<PemPair> {
    let owned = files.clone();
    let seen = Arc::clone(&current);
    let outcome = tokio::task::spawn_blocking(move || check(&owned, &seen)).await;
    settle(resolver, current, outcome)
}

/// Applies what the blocking look at the files found; a look that panicked or was cancelled is
/// logged and leaves the pair in force.
fn settle(
    resolver: &ReloadableCertificate,
    current: Arc<PemPair>,
    outcome: Result<Checked, tokio::task::JoinError>,
) -> Arc<PemPair> {
    match outcome {
        Ok(checked) => apply(resolver, current, checked),
        Err(error) => {
            log_reload_failed(&error);
            current
        }
    }
}

/// Completes when the stop flag is set.
async fn stopped(mut stopping: watch::Receiver<bool>) {
    drop(stopping.wait_for(|stopping| *stopping).await);
}

/// Replaces the pair of the resolver when the files change, until the stop flag is set.
///
/// The files are compared with `loaded` every `interval`. A pair that changed and parses becomes
/// the pair of every later handshake; one that does not parse is logged and leaves the last valid
/// pair in force.
pub async fn watch_files(
    resolver: Arc<ReloadableCertificate>,
    files: TlsFiles,
    loaded: PemPair,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
) {
    let mut current = Arc::new(loaded);
    loop {
        tokio::select! {
            () = stopped(shutdown.clone()) => return,
            () = tokio::time::sleep(interval) => {}
        }
        current = reload(&resolver, &files, current).await;
    }
}

/// Accepts TCP connections, runs their TLS handshakes concurrently and hands the finished ones to
/// the server, so that a slow client delays nobody.
#[derive(Debug)]
pub struct TlsListener {
    completed: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    /// Starts accepting on `listener` with `config`. The accept task ends when this value is
    /// dropped, which closes the socket.
    ///
    /// # Errors
    ///
    /// Returns the error of reading the local address of the socket.
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let (sender, completed) = mpsc::channel(COMPLETED_HANDSHAKES);
        tokio::spawn(accept_loop(listener, TlsAcceptor::from(config), sender));
        Ok(Self { completed, local })
    }
}

type Handshake = (TlsStream<TcpStream>, SocketAddr);

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<Handshake>,
) {
    loop {
        tokio::select! {
            () = sender.closed() => return,
            accepted = listener.accept() => accept_one(accepted, &acceptor, &sender).await,
        }
    }
}

async fn accept_one(
    accepted: io::Result<(TcpStream, SocketAddr)>,
    acceptor: &TlsAcceptor,
    sender: &mpsc::Sender<Handshake>,
) {
    match accepted {
        Ok((stream, peer)) => {
            tokio::spawn(handshake(acceptor.clone(), stream, peer, sender.clone()));
        }
        Err(error) => {
            log_accept_failed(&error);
            tokio::time::sleep(ACCEPT_BACKOFF).await;
        }
    }
}

async fn handshake(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    sender: mpsc::Sender<Handshake>,
) {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(secured)) => drop(sender.send((secured, peer)).await),
        Ok(Err(error)) => log_handshake_failed(peer, &error),
        Err(_elapsed) => log_handshake_timed_out(peer),
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.completed.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// The router of the public listener until the pipeline of Story 10.2 exists: every request is
/// answered with 503 `iam_stale` and `Retry-After: 1`, because no snapshot is published.
pub fn stale_router() -> Router {
    Router::new().fallback(iam_stale)
}

async fn iam_stale() -> Response {
    stale_response("No policy snapshot is published yet.")
}

/// 503 `iam_stale` with `Retry-After: 1`.
fn stale_response(detail: &'static str) -> Response {
    let problem = Problem {
        r#type: TYPE_IAM_STALE,
        ..Problem::new(StatusCode::SERVICE_UNAVAILABLE).with_detail(detail)
    };
    let mut response = problem.into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// What the snapshot step of the public listener reads: the published snapshot and the freshness of
/// the pod (Story 9.5).
#[derive(Debug, Clone)]
struct Gate {
    freshness: Arc<FreshnessState>,
    view: Arc<dyn PolicyView>,
}

/// The router of the public listener until the pipeline of Story 10.2 exists.
///
/// Its snapshot step is the one the pipeline will have: a request is allowed to proceed only while a snapshot is
/// published and `FreshnessRule` finds the pod fresh, that is, a proof no older than
/// `FRESHNESS_HARD_BOUND` and no gap above `FRESHNESS_READY_BOUND` since it; any other request is
/// answered 503 `iam_stale` with `Retry-After: 1`. A request that proceeds meets no route yet and
/// is answered with the 404 problem.
pub fn public_router(freshness: Arc<FreshnessState>, view: Arc<dyn PolicyView>) -> Router {
    Router::new()
        .fallback(snapshot_step)
        .with_state(Gate { freshness, view })
}

async fn snapshot_step(State(gate): State<Gate>) -> Response {
    if gate.view.current().is_some() && gate.freshness.is_fresh() {
        not_found().await.into_response()
    } else {
        stale_response("The policy snapshot is not proven fresh.")
    }
}

fn log_reloaded() {
    tracing::info!("gateway certificate reloaded");
}

fn log_rejected(error: &CertificateError) {
    tracing::error!(error = %error, "gateway certificate reload failed, the last valid pair stays in force");
}

fn log_reload_failed(error: &tokio::task::JoinError) {
    tracing::error!(error = %error, "gateway certificate reload task failed");
}

fn log_accept_failed(error: &io::Error) {
    tracing::warn!(error = %error, "accepting a connection failed");
}

fn log_handshake_failed(peer: SocketAddr, error: &io::Error) {
    tracing::debug!(%peer, error = %error, "TLS handshake failed");
}

fn log_handshake_timed_out(peer: SocketAddr) {
    tracing::debug!(%peer, "TLS handshake timed out");
}

#[cfg(test)]
mod tests;
