//! The edge of the public listener (Story 10.9, FR-67, NFR-21, NFR-40) over real loopback
//! sockets: the production pipeline with the production forwarder, an echo upstream, and the
//! connection loop that bounds every connection. The first smuggling corpus runs here: no request
//! is read differently by the gateway and the upstream.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use http_body_util::{BodyExt as _, Empty};
use hyper::Request;
use hyper::body::Frame;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use service::bootstrap::gateway::edge::{Edge, EdgeLimits, proxy};
use service::bootstrap::gateway::shedding::{ConnectionSignals, serve_with_edge};
use test_support::seed::TestRng;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use super::proxy::proxy_over;
use super::{GOOD, HOST, snapshot};

const LIMIT: Duration = Duration::from_secs(10);

/// What the echo upstream saw and what it holds back.
#[derive(Debug, Default)]
struct Upstream {
    headers: Mutex<Vec<HeaderMap>>,
    entered: Notify,
    release: Notify,
    streamed: AtomicU64,
}

impl Upstream {
    fn received(&self) -> Vec<HeaderMap> {
        self.headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// `/api/users/blocked` waits until released, `/api/users/big` streams 64 KiB chunks for as long as
/// it is read, every other id answers at once.
async fn echo(
    State(upstream): State<Arc<Upstream>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    upstream
        .headers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(headers);
    match id.as_str() {
        "blocked" => {
            upstream.entered.notify_one();
            upstream.release.notified().await;
            "released".into_response()
        }
        "big" => big(upstream),
        _ => "echo".into_response(),
    }
}

fn big(upstream: Arc<Upstream>) -> Response {
    (StatusCode::OK, Body::new(Endless(upstream))).into_response()
}

/// A body of 64 KiB chunks that never ends: it is polled only as fast as the client reads.
struct Endless(Arc<Upstream>);

impl hyper::body::Body for Endless {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.streamed.fetch_add(65_536, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0_u8; 65_536])))))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// A running gateway: its address, the echo upstream behind it and the stop flag.
struct Rig {
    address: SocketAddr,
    upstream: Arc<Upstream>,
    stop: watch::Sender<bool>,
    server: JoinHandle<io::Result<()>>,
}

impl Rig {
    async fn finish(self) {
        self.stop.send_replace(true);
        timeout(LIMIT, self.server).await.unwrap().unwrap().unwrap();
    }
}

async fn start(edge: Edge) -> Rig {
    let upstream = Arc::new(Upstream::default());
    let upstream_listener = bound().await;
    let upstream_address = upstream_listener.local_addr().unwrap();
    let echo_router = Router::new()
        .route("/api/users/{id}", get(echo))
        .with_state(Arc::clone(&upstream));
    drop(tokio::spawn(async move {
        axum::serve(upstream_listener, echo_router).await
    }));
    let mut rng = TestRng::from_env();
    let (router, _clock) = proxy_over(upstream_address, snapshot(&mut rng, true));
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = watch::channel(false);
    let server = tokio::spawn(serve_with_edge(
        listener,
        router,
        ConnectionSignals::new(stopping, None),
        edge,
    ));
    Rig {
        address,
        upstream,
        stop,
        server,
    }
}

fn plain() -> Edge {
    Edge::new(EdgeLimits::default(), false, None)
}

#[expect(
    clippy::disallowed_methods,
    reason = "a test connects to its own gateway on loopback"
)]
async fn connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

fn get_user(id: &str) -> String {
    format!("GET /api/users/{id} HTTP/1.1\r\nhost: {HOST}\r\nauthorization: Bearer {GOOD}\r\n")
}

/// Writes `bytes` and reads until the gateway closes the connection.
async fn exchange(address: SocketAddr, bytes: &[u8]) -> String {
    let mut stream = connect(address).await;
    stream.write_all(bytes).await.unwrap();
    let mut text = Vec::new();
    // A refused connection may end with a reset rather than an orderly close.
    timeout(LIMIT, stream.read_to_end(&mut text))
        .await
        .unwrap()
        .unwrap_or_default();
    String::from_utf8_lossy(&text).into_owned()
}

fn status_line(answer: &str) -> &str {
    answer.lines().next().unwrap_or_default()
}

fn client(id: &str) -> Request<Empty<Bytes>> {
    Request::get(format!("/api/users/{id}"))
        .header("host", HOST)
        .header("authorization", format!("Bearer {GOOD}"))
        .body(Empty::new())
        .unwrap()
}

fn anonymous(id: &str) -> Request<Empty<Bytes>> {
    Request::get(format!("/api/users/{id}"))
        .header("host", HOST)
        .body(Empty::new())
        .unwrap()
}

async fn h1(address: SocketAddr) -> (http1::SendRequest<Empty<Bytes>>, JoinHandle<()>) {
    let (sender, connection) = http1::handshake(TokioIo::new(connect(address).await))
        .await
        .unwrap();
    let ended = tokio::spawn(async move {
        connection.await.unwrap_or_default();
    });
    (sender, ended)
}

async fn h2(address: SocketAddr) -> (http2::SendRequest<Empty<Bytes>>, JoinHandle<()>) {
    let (sender, connection) =
        http2::handshake(TokioExecutor::new(), TokioIo::new(connect(address).await))
            .await
            .unwrap();
    let ended = tokio::spawn(async move {
        connection.await.unwrap_or_default();
    });
    (sender, ended)
}

/// A Proxy Protocol v2 header of a `PROXY` command that names `client` over TCP and IPv4.
fn proxy_header(client: [u8; 4]) -> Vec<u8> {
    let mut header = proxy::SIGNATURE.to_vec();
    header.extend([0x21, 0x11, 0x00, 0x0C]);
    header.extend(client);
    header.extend([10, 0, 0, 1]);
    header.extend([0x30, 0x39, 0x01, 0xBB]);
    header
}

#[tokio::test]
async fn the_proxy_protocol_header_names_the_client_and_a_connection_without_one_is_closed() {
    let edge = Edge::new(EdgeLimits::default(), true, None).reading_header_in_serve(true);
    let rig = start(edge).await;
    let mut proxied = proxy_header([203, 0, 113, 9]);
    proxied.extend(
        format!("{}connection: close\r\n\r\n", get_user("1"))
            .as_bytes()
            .iter(),
    );

    let first = exchange(rig.address, &proxied).await;
    let second = exchange(
        rig.address,
        format!("{}connection: close\r\n\r\n", get_user("1")).as_bytes(),
    )
    .await;

    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    assert_eq!(second, "");
    let received = rig.upstream.received();
    assert_eq!(received.len(), 1);
    let forwarded = received
        .first()
        .and_then(|headers| headers.get("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(forwarded.starts_with("203.0.113.9"), "{forwarded}");
    rig.finish().await;
}

#[tokio::test]
async fn a_header_block_of_17_kib_gets_431() {
    let rig = start(plain()).await;
    let request = format!(
        "{}x-padding: {}\r\nconnection: close\r\n\r\n",
        get_user("1"),
        "a".repeat(17 * 1024)
    );

    let answer = exchange(rig.address, request.as_bytes()).await;

    assert!(
        status_line(&answer).contains("431"),
        "{}",
        status_line(&answer)
    );
    assert_eq!(rig.upstream.received().len(), 0);
    rig.finish().await;
}

#[tokio::test(start_paused = true)]
async fn a_client_that_sends_its_headers_too_slowly_is_closed_after_10_seconds() {
    let rig = start(plain()).await;
    let mut stream = connect(rig.address).await;
    stream.write_all(get_user("1").as_bytes()).await.unwrap();
    let started = Instant::now();

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap_or_default();

    assert!(started.elapsed() >= Duration::from_secs(10));
    assert_eq!(rig.upstream.received().len(), 0);
    rig.finish().await;
}

#[tokio::test]
async fn the_65th_connection_of_an_address_is_refused() {
    let rig = start(plain()).await;
    let mut held = Vec::new();
    for _ in 0..64 {
        let (mut sender, ended) = h1(rig.address).await;
        sender.ready().await.unwrap();
        // No token: the connection is counted by its address and claims no subject.
        let response = sender.send_request(anonymous("1")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        response.into_body().collect().await.unwrap();
        held.push((sender, ended));
    }

    let mut refused = connect(rig.address).await;
    let mut received = Vec::new();
    timeout(LIMIT, refused.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap_or_default();

    assert_eq!(received, Vec::<u8>::new());
    drop(held);
    rig.finish().await;
}

#[tokio::test]
async fn the_33rd_connection_of_a_subject_is_refused() {
    let rig = start(plain()).await;
    let mut held = Vec::new();
    for _ in 0..32 {
        let (mut sender, ended) = h1(rig.address).await;
        sender.ready().await.unwrap();
        let response = sender.send_request(client("1")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
        held.push((sender, ended));
    }

    let (mut sender, _ended) = h1(rig.address).await;
    sender.ready().await.unwrap();
    let refused = sender.send_request(client("1")).await.unwrap();

    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rig.upstream.received().len(), 32);
    drop(held);
    rig.finish().await;
}

#[tokio::test]
async fn a_connection_that_reached_its_age_gets_goaway_and_its_in_flight_stream_completes() {
    let limits = EdgeLimits {
        connection_age: Duration::from_millis(500),
        age_jitter_percent: 0,
        ..EdgeLimits::default()
    };
    let rig = start(Edge::new(limits, false, None)).await;
    let (mut sender, ended) = h2(rig.address).await;
    sender.ready().await.unwrap();
    let in_flight = tokio::spawn(sender.send_request(client("blocked")));
    timeout(LIMIT, rig.upstream.entered.notified())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let late = match sender.ready().await {
        Ok(()) => sender.send_request(client("1")).await.map(|_| ()),
        Err(error) => Err(error),
    };
    rig.upstream.release.notify_one();
    let response = timeout(LIMIT, in_flight).await.unwrap().unwrap().unwrap();

    assert!(late.is_err(), "a stream opened after GOAWAY must fail");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "released");
    timeout(LIMIT, ended).await.unwrap().unwrap();
    rig.finish().await;
}

#[tokio::test]
async fn ambiguous_framing_gets_400_and_never_reaches_the_upstream() {
    let rig = start(plain()).await;
    let corpus = [
        "content-length: 4\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
        "content-length: 4\r\ncontent-length: 5\r\n\r\nabcd",
        "content-length: 4, 5\r\n\r\nabcd",
        "content-length: +4\r\n\r\nabcd",
        "content-length: 4\r\ntransfer-encoding: identity\r\n\r\nabcd",
    ];

    for tail in corpus {
        let request = format!("{}connection: close\r\n{tail}", get_user("1"));
        let answer = exchange(rig.address, request.as_bytes()).await;
        assert!(
            status_line(&answer).contains("400"),
            "{tail:?} -> {}",
            status_line(&answer)
        );
    }

    assert_eq!(rig.upstream.received().len(), 0);
    rig.finish().await;
}

#[tokio::test]
async fn an_invalid_http2_path_gets_400() {
    let rig = start(plain()).await;
    let (mut sender, _ended) = h2(rig.address).await;
    sender.ready().await.unwrap();
    let request = Request::builder()
        .method("OPTIONS")
        .uri("*")
        .header("host", HOST)
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = sender.send_request(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rig.upstream.received().len(), 0);
    rig.finish().await;
}

#[tokio::test]
async fn a_hop_by_hop_header_named_by_connection_never_reaches_the_upstream() {
    let rig = start(plain()).await;
    let request = format!(
        "{}connection: keep-alive, X-IAM-Subject, close\r\nx-iam-subject: forged\r\nkeep-alive: timeout=5\r\n\r\n",
        get_user("1")
    );

    let answer = exchange(rig.address, request.as_bytes()).await;

    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    let received = rig.upstream.received();
    let headers = received.first().unwrap();
    assert!(headers.get("x-iam-subject").is_none());
    assert!(headers.get("keep-alive").is_none());
    assert!(
        headers
            .get_all("connection")
            .iter()
            .all(|value| !value.as_bytes().eq_ignore_ascii_case(b"keep-alive"))
    );
    rig.finish().await;
}

#[tokio::test]
async fn a_client_that_stops_reading_stops_the_upstream_and_leaves_other_connections_alone() {
    let rig = start(plain()).await;
    let mut stalled = connect(rig.address).await;
    stalled
        .write_all(format!("{}\r\n", get_user("big")).as_bytes())
        .await
        .unwrap();
    timeout(LIMIT, async {
        while rig.upstream.streamed.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let first = settled(&rig.upstream).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let second = rig.upstream.streamed.load(Ordering::SeqCst);

    assert_eq!(first, second, "the upstream kept being read");
    assert!(first < 64 * 1024 * 1024, "{first} bytes were pulled");
    let (mut sender, _ended) = h1(rig.address).await;
    sender.ready().await.unwrap();
    let response = sender.send_request(client("1")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(stalled);
    rig.finish().await;
}

/// The bytes the upstream streamed once they stopped growing for 200 ms.
async fn settled(upstream: &Upstream) -> u64 {
    let mut last = upstream.streamed.load(Ordering::SeqCst);
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = upstream.streamed.load(Ordering::SeqCst);
        if now == last {
            return now;
        }
        last = now;
    }
}
