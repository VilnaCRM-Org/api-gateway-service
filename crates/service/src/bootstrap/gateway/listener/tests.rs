use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use test_support::log::LogRecorder;
use test_support::tls::{CertificateFiles, self_signed};
use tokio::sync::watch;
use tower::ServiceExt as _;

use super::*;

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// A directory of this test, removed when the value is dropped.
struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let number = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("service-listener-{}-{number}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

fn files_of(pair: &CertificateFiles) -> TlsFiles {
    TlsFiles {
        cert: pair.cert.clone(),
        key: pair.key.clone(),
    }
}

fn first_certificate(key: &CertifiedKey) -> Vec<u8> {
    key.cert.first().unwrap().as_ref().to_vec()
}

#[test]
fn a_matching_pair_loads() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");

    let (key, source) = load_with_source(&files_of(&pair)).unwrap();

    assert_eq!(key.cert.len(), 1);
    assert_eq!(source, read_pair(&files_of(&pair)).unwrap());
    assert!(load_certified_key(&files_of(&pair)).is_ok());
}

#[test]
fn a_missing_file_is_a_read_error_naming_the_file() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    let missing_key = TlsFiles {
        cert: pair.cert,
        key: directory.path().join("absent.pem"),
    };
    let missing_cert = TlsFiles {
        cert: directory.path().join("absent.pem"),
        key: pair.key,
    };

    let key = load_certified_key(&missing_key).unwrap_err();
    let cert = load_certified_key(&missing_cert).unwrap_err();

    assert!(
        key.to_string()
            .starts_with("the private key cannot be read")
    );
    assert!(
        cert.to_string()
            .starts_with("the certificate chain cannot be read")
    );
}

#[test]
fn a_certificate_file_without_a_certificate_is_refused() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    std::fs::write(&pair.cert, "not a certificate").unwrap();

    let error = load_certified_key(&files_of(&pair)).unwrap_err();

    assert!(matches!(error, CertificateError::NoCertificate), "{error}");
}

#[test]
fn a_key_file_without_a_key_is_refused_without_echoing_it() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    std::fs::write(&pair.key, "secret-looking garbage").unwrap();

    let error = load_certified_key(&files_of(&pair)).unwrap_err();

    assert!(
        matches!(
            error,
            CertificateError::Pem {
                file: "private key",
                ..
            }
        ),
        "{error}"
    );
    assert!(!error.to_string().contains("secret-looking"));
}

#[test]
fn a_key_of_another_certificate_is_refused() {
    let directory = Directory::new();
    let first = self_signed(directory.path(), "first", "first");
    let second = self_signed(directory.path(), "second", "second");
    let mixed = TlsFiles {
        cert: first.cert,
        key: second.key,
    };

    let error = load_certified_key(&mixed).unwrap_err();

    assert!(matches!(error, CertificateError::Key(_)), "{error}");
}

#[test]
fn the_resolver_presents_the_pair_in_force_and_the_replacement_after_it() {
    let directory = Directory::new();
    let first = self_signed(directory.path(), "first", "first");
    let second = self_signed(directory.path(), "second", "second");
    let first_key = load_certified_key(&files_of(&first)).unwrap();
    let second_key = load_certified_key(&files_of(&second)).unwrap();
    let expected_first = first_certificate(&first_key);
    let expected_second = first_certificate(&second_key);
    let resolver = ReloadableCertificate::new(first_key);

    assert_eq!(first_certificate(&resolver.current()), expected_first);
    resolver.replace(second_key);

    assert_eq!(first_certificate(&resolver.current()), expected_second);
    assert_ne!(expected_first, expected_second);
}

#[test]
fn the_server_config_offers_h2_and_http_1_1() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    let key = load_certified_key(&files_of(&pair)).unwrap();

    let config = server_config(Arc::new(ReloadableCertificate::new(key))).unwrap();

    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the condition did not become true in time");
}

#[tokio::test]
async fn the_watcher_replaces_the_pair_and_keeps_the_last_valid_one_after_a_failed_reload() {
    let directory = Directory::new();
    let first = self_signed(directory.path(), "live", "first");
    let files = files_of(&first);
    let (key, loaded) = load_with_source(&files).unwrap();
    let original = first_certificate(&key);
    let resolver = Arc::new(ReloadableCertificate::new(key));
    let (stop, stopping) = watch::channel(false);
    let watcher = tokio::spawn(watch_files(
        Arc::clone(&resolver),
        files.clone(),
        loaded,
        Duration::from_millis(10),
        stopping,
    ));

    let next = self_signed(directory.path(), "next", "second");
    std::fs::copy(&next.key, &files.key).unwrap();
    std::fs::copy(&next.cert, &files.cert).unwrap();
    let replacement = first_certificate(&load_certified_key(&files_of(&next)).unwrap());
    eventually(|| first_certificate(&resolver.current()) == replacement).await;
    std::fs::write(&files.cert, "unparsable").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_ne!(original, replacement);
    assert_eq!(first_certificate(&resolver.current()), replacement);
    stop.send_replace(true);
    watcher.await.unwrap();
}

#[tokio::test]
async fn the_watcher_recovers_when_a_valid_pair_follows_an_unparsable_one() {
    let directory = Directory::new();
    let first = self_signed(directory.path(), "live", "first");
    let files = files_of(&first);
    let (key, loaded) = load_with_source(&files).unwrap();
    let resolver = Arc::new(ReloadableCertificate::new(key));
    let (stop, stopping) = watch::channel(false);
    let watcher = tokio::spawn(watch_files(
        Arc::clone(&resolver),
        files.clone(),
        loaded,
        Duration::from_millis(10),
        stopping,
    ));
    std::fs::write(&files.cert, "unparsable").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let next = self_signed(directory.path(), "next", "second");
    std::fs::copy(&next.key, &files.key).unwrap();
    std::fs::copy(&next.cert, &files.cert).unwrap();
    let replacement = first_certificate(&load_certified_key(&files_of(&next)).unwrap());

    eventually(|| first_certificate(&resolver.current()) == replacement).await;
    stop.send_replace(true);
    watcher.await.unwrap();
}

#[tokio::test]
async fn the_watcher_ends_when_the_stop_flag_is_set() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "live", "first");
    let files = files_of(&pair);
    let (key, loaded) = load_with_source(&files).unwrap();
    let (stop, stopping) = watch::channel(false);
    let watcher = tokio::spawn(watch_files(
        Arc::new(ReloadableCertificate::new(key)),
        files,
        loaded,
        Duration::from_secs(3600),
        stopping,
    ));

    stop.send_replace(true);

    tokio::time::timeout(Duration::from_secs(5), watcher)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_file_that_vanishes_leaves_the_pair_in_force() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "live", "first");
    let files = files_of(&pair);
    let (key, loaded) = load_with_source(&files).unwrap();
    let original = first_certificate(&key);
    let resolver = Arc::new(ReloadableCertificate::new(key));
    let (stop, stopping) = watch::channel(false);
    let watcher = tokio::spawn(watch_files(
        Arc::clone(&resolver),
        files.clone(),
        loaded,
        Duration::from_millis(10),
        stopping,
    ));

    std::fs::remove_file(&files.cert).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(first_certificate(&resolver.current()), original);
    stop.send_replace(true);
    watcher.await.unwrap();
}

#[tokio::test]
async fn every_request_to_the_public_router_is_a_503_iam_stale_with_retry_after() {
    for (method, path) in [("GET", "/"), ("POST", "/api/users"), ("DELETE", "/x?y=1")] {
        let response = stale_router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["type"], TYPE_IAM_STALE);
        assert_eq!(document["status"], 503);
    }
}

#[test]
fn a_pem_pair_never_prints_its_bytes() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");

    let source = read_pair(&files_of(&pair)).unwrap();

    assert_eq!(format!("{source:?}"), "PemPair { .. }");
}

#[test]
fn a_certificate_file_with_broken_pem_is_a_pem_error_of_the_chain() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    std::fs::write(
        &pair.cert,
        "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let error = load_certified_key(&files_of(&pair)).unwrap_err();

    assert!(
        matches!(
            error,
            CertificateError::Pem {
                file: "certificate chain",
                ..
            }
        ),
        "{error}"
    );
}

#[tokio::test]
async fn a_look_at_the_files_that_did_not_finish_is_logged_and_keeps_the_pair() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "live", "first");
    let (key, loaded) = load_with_source(&files_of(&pair)).unwrap();
    let original = first_certificate(&key);
    let resolver = ReloadableCertificate::new(key);
    let current = Arc::new(loaded);
    let look = tokio::spawn(std::future::pending::<Checked>());
    look.abort();
    let cancelled = look.await;

    let (recorder, guard) = LogRecorder::install();
    let kept = settle(&resolver, Arc::clone(&current), cancelled);
    drop(guard);

    assert!(Arc::ptr_eq(&kept, &current));
    assert_eq!(first_certificate(&resolver.current()), original);
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "gateway certificate reload task failed");
}

/// An acceptor over a fresh self-signed pair; the directory holds the files.
fn acceptor() -> (TlsAcceptor, Directory) {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    let key = load_certified_key(&files_of(&pair)).unwrap();
    let config = server_config(Arc::new(ReloadableCertificate::new(key))).unwrap();
    (TlsAcceptor::from(config), directory)
}

/// A socket bound to an ephemeral loopback port.
#[expect(
    clippy::disallowed_methods,
    reason = "the test opens the socket the listener works on"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// A connection to `address`, as a client opens it.
#[expect(
    clippy::disallowed_methods,
    reason = "the test opens the connection the listener works on"
)]
async fn connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

/// The server side of a loopback connection, the client side and the address of the client.
async fn connected() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = bound().await;
    let client = connect(listener.local_addr().unwrap()).await;
    let (server, peer) = listener.accept().await.unwrap();
    (server, client, peer)
}

/// A server certificate verifier that accepts exactly one certificate: the self-signed test
/// certificate carries the CA flag, which the web PKI refuses for a server.
#[derive(Debug)]
struct Pinned {
    certificate: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        (end_entity.as_ref() == self.certificate.as_slice())
            .then(ServerCertVerified::assertion)
            .ok_or(rustls::Error::General("another certificate".to_owned()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS client that trusts only the certificate of `pair`.
fn connector(pair: &CertificateFiles) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(default_provider());
    let certificate = CertificateDer::from_pem_file(&pair.cert).unwrap().to_vec();
    let verifier = Arc::new(Pinned {
        certificate,
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn a_completed_handshake_reaches_the_server_with_the_address_of_the_client() {
    let directory = Directory::new();
    let pair = self_signed(directory.path(), "valid", "valid");
    let key = load_certified_key(&files_of(&pair)).unwrap();
    let config = server_config(Arc::new(ReloadableCertificate::new(key))).unwrap();
    let mut listener = TlsListener::new(bound().await, config).unwrap();
    let address = Listener::local_addr(&listener).unwrap();
    let connector = connector(&pair);

    let client = tokio::spawn(async move {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        connector
            .connect(name, connect(address).await)
            .await
            .unwrap()
    });
    let (_secured, peer) =
        tokio::time::timeout(Duration::from_secs(10), Listener::accept(&mut listener))
            .await
            .unwrap();
    let secured_client = client.await.unwrap();

    assert_eq!(peer, secured_client.get_ref().0.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn a_failed_accept_is_logged_and_hands_nothing_to_the_server() {
    let (acceptor, _directory) = acceptor();
    let (sender, mut completed) = mpsc::channel(1);

    let (recorder, guard) = LogRecorder::install();
    accept_one(
        Err(io::Error::other("too many open files")),
        &acceptor,
        &sender,
        &plain_edge(),
    )
    .await;
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "accepting a connection failed");
    assert!(completed.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_client_that_never_finishes_the_handshake_is_dropped_after_the_timeout() {
    let (acceptor, _directory) = acceptor();
    let (server_side, _client, peer) = connected().await;
    let (sender, mut completed) = mpsc::channel(1);

    let (recorder, guard) = LogRecorder::install();
    handshake(acceptor, server_side, peer, sender, plain_edge()).await;
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "TLS handshake timed out");
    assert!(completed.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_listener_whose_accept_task_ended_waits_and_still_reports_its_address() {
    let (sender, completed) = mpsc::channel(1);
    drop(sender);
    let local = SocketAddr::from(([127, 0, 0, 1], 4443));
    let mut listener = TlsListener { completed, local };

    assert_eq!(Listener::local_addr(&listener).unwrap(), local);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), Listener::accept(&mut listener))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_client_that_speaks_no_tls_fails_the_handshake_and_is_logged() {
    use tokio::io::AsyncWriteExt as _;

    let (acceptor, _directory) = acceptor();
    let (server_side, mut client, peer) = connected().await;
    let (sender, mut completed) = mpsc::channel(1);
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();

    let (recorder, guard) = LogRecorder::install();
    handshake(acceptor, server_side, peer, sender, plain_edge()).await;
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "TLS handshake failed");
    assert!(completed.try_recv().is_err());
}

#[tokio::test]
async fn the_accept_loop_ends_once_nobody_takes_the_finished_handshakes() {
    let (acceptor, _directory) = acceptor();
    let (sender, completed) = mpsc::channel(1);
    drop(completed);

    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        accept_loop(bound().await, acceptor, sender, plain_edge()),
    )
    .await;

    assert!(ended.is_ok());
}

fn plain_edge() -> Edge {
    Edge::new(EdgeLimits::default(), false, None)
}

fn proxy_edge() -> Edge {
    Edge::new(EdgeLimits::default(), true, None)
}

fn proxy_v2_header(source: [u8; 4], port: u16) -> Vec<u8> {
    let mut bytes = proxy::SIGNATURE.to_vec();
    bytes.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&[10, 0, 0, 1]);
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&8443_u16.to_be_bytes());
    bytes
}

#[tokio::test]
async fn a_connection_with_a_proxy_header_takes_the_client_address_of_the_header() {
    use tokio::io::AsyncWriteExt as _;

    let (server_side, mut client, peer) = connected().await;

    client
        .write_all(&proxy_v2_header([203, 0, 113, 7], 51000))
        .await
        .unwrap();
    let mut stream = server_side;
    let client_address = client_of(&mut stream, peer, &proxy_edge()).await;

    assert_eq!(client_address, Some("203.0.113.7:51000".parse().unwrap()));
}

#[tokio::test]
async fn a_connection_without_a_proxy_header_is_closed_and_logged() {
    use tokio::io::AsyncWriteExt as _;

    let (mut server_side, mut client, peer) = connected().await;
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();

    let (recorder, guard) = LogRecorder::install();
    let client_address = client_of(&mut server_side, peer, &proxy_edge()).await;
    drop(guard);

    assert_eq!(client_address, None);
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0].message,
        "connection without a valid Proxy Protocol header closed"
    );
}

#[tokio::test]
async fn an_edge_without_the_proxy_protocol_keeps_the_address_of_the_socket() {
    let (mut server_side, _client, peer) = connected().await;

    let client_address = client_of(&mut server_side, peer, &plain_edge()).await;

    assert_eq!(client_address, Some(peer));
}

#[tokio::test]
async fn a_connection_without_a_proxy_header_never_reaches_the_tls_handshake() {
    use tokio::io::AsyncWriteExt as _;

    let (acceptor, _directory) = acceptor();
    let (server_side, mut client, peer) = connected().await;
    let (sender, mut completed) = mpsc::channel(1);
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();

    let (recorder, guard) = LogRecorder::install();
    handshake(acceptor, server_side, peer, sender, proxy_edge()).await;
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0].message,
        "connection without a valid Proxy Protocol header closed"
    );
    assert!(completed.try_recv().is_err());
}
