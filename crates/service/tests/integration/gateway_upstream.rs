//! The `HyperUpstreamForwarder` of Story 10.3 against real upstreams on loopback sockets: the
//! response is relayed as it arrives, the request body is streamed under the limit of the route,
//! and a refused connection and an upstream that never answers are told apart from a body that is
//! too large.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use http_body_util::BodyExt as _;
use hyper::body::{Frame, SizeHint};
use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{
    BodyLimit, EndpointConditions, EndpointParts, EndpointSlice, ForwardError, RouteId,
    UpstreamEndpoint, UpstreamForwarder as _, UpstreamName, UpstreamProtocol, UpstreamSettings,
    UpstreamSettingsDraft, UpstreamTarget, WatchTarget,
};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use shared_domain::Uuid;
use test_support::rng::FakeRng;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Notify, mpsc};

const BOUND: Duration = Duration::from_secs(10);

fn service() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

fn forwarder(address: SocketAddr) -> HyperUpstreamForwarder {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    directory.replace(
        &service(),
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints: vec![UpstreamEndpoint::new(EndpointParts {
                address: address.ip().to_string(),
                port: address.port(),
                zone: None,
                pod: None,
                conditions: EndpointConditions::healthy(),
            })],
        }],
    );
    HyperUpstreamForwarder::new(directory.view(), true, Arc::new(FakeRng::seeded(1)))
}

fn target(protocol: UpstreamProtocol, body_limit: i64) -> UpstreamTarget {
    target_answering_within(protocol, body_limit, 10_000)
}

fn target_answering_within(
    protocol: UpstreamProtocol,
    body_limit: i64,
    response_timeout_ms: i64,
) -> UpstreamTarget {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms,
        concurrency_limit: 100,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();
    UpstreamTarget::new(
        UpstreamName::new("user-service").unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    )
    .with_settings(&settings)
    .with_body_limit(BodyLimit::new(body_limit).unwrap())
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake upstream on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Serves `router` on a free loopback port, over HTTP/1.1 and cleartext HTTP/2.
async fn serve(router: Router) -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    address
}

/// What the fake upstream saw.
#[derive(Debug, Clone, Default)]
struct Seen {
    requests: Arc<AtomicUsize>,
}

async fn echo(State(seen): State<Seen>, headers: HeaderMap, body: Bytes) -> Response {
    seen.requests.fetch_add(1, Ordering::SeqCst);
    let hop = headers.contains_key("x-hop");
    let kept = headers
        .get("x-kept")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    (
        StatusCode::CREATED,
        [
            ("x-upstream", "yes"),
            ("x-hop-seen", if hop { "yes" } else { "no" }),
        ],
        format!("{kept}:{}", body.len()),
    )
        .into_response()
}

async fn text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn the_response_of_the_upstream_is_relayed_unchanged() {
    let seen = Seen::default();
    let address = serve(
        Router::new()
            .route("/echo", post(echo))
            .with_state(seen.clone()),
    )
    .await;
    let request = Request::post("/echo?x=1")
        .header("x-kept", "kept")
        .header("connection", "x-hop")
        .header("x-hop", "dropped")
        .body(Body::from("12345"))
        .unwrap();

    let response = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 1_024), request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get("x-upstream").unwrap(), "yes");
    assert_eq!(response.headers().get("x-hop-seen").unwrap(), "no");
    assert_eq!(text(response).await, "kept:5");
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_upstream_that_speaks_cleartext_http2_is_reached_over_one_connection() {
    let seen = Seen::default();
    let address = serve(
        Router::new()
            .route("/echo", post(echo))
            .with_state(seen.clone()),
    )
    .await;
    let forwarder = forwarder(address);

    for _ in 0..2 {
        let request = Request::post("/echo").body(Body::from("123")).unwrap();
        let response = forwarder
            .forward(target(UpstreamProtocol::H2c, 1_024), request)
            .await
            .unwrap();
        assert_eq!(text(response).await, ":3");
    }

    assert_eq!(seen.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_body_declared_above_the_limit_is_refused_before_the_upstream_sees_anything() {
    let seen = Seen::default();
    let address = serve(
        Router::new()
            .route("/echo", post(echo))
            .with_state(seen.clone()),
    )
    .await;
    let request = Request::post("/echo")
        .header("content-length", "5")
        .body(Body::from("12345"))
        .unwrap();

    let outcome = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 4), request)
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::BodyTooLarge);
    assert_eq!(seen.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_streamed_body_that_grows_above_the_limit_is_cut_off() {
    let address = serve(
        Router::new()
            .route("/echo", post(echo))
            .with_state(Seen::default()),
    )
    .await;
    let (sender, chunks) = chunked();
    sender.send(Bytes::from_static(b"123")).await.unwrap();
    sender.send(Bytes::from_static(b"456")).await.unwrap();
    drop(sender);
    let request = Request::post("/echo").body(chunks).unwrap();

    let outcome = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 4), request)
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::BodyTooLarge);
}

#[tokio::test]
async fn a_connection_that_is_refused_means_the_request_was_not_sent() {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(listener);
    let request = Request::get("/echo").body(Body::empty()).unwrap();

    let outcome = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 1_024), request)
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NotSent);
}

#[tokio::test]
async fn an_upstream_that_closes_the_connection_without_answering_is_an_upstream_failure() {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        drop(stream);
    }));
    let request = Request::get("/echo").body(Body::empty()).unwrap();

    let outcome = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 1_024), request)
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::Upstream);
}

/// A listener on `[::1]` whose queue of connections is full and that never accepts: a connect to
/// it stays pending. The returned streams keep the queue full until they drop.
#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake upstream on a free loopback port"
)]
async fn blocked_listener() -> (TcpListener, SocketAddr, Vec<TcpStream>) {
    let socket = TcpSocket::new_v6().unwrap();
    socket.bind("[::1]:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1).unwrap();
    let address = listener.local_addr().unwrap();
    let mut queued = Vec::new();
    for _ in 0..2 {
        queued.push(TcpStream::connect(address).await.unwrap());
    }
    (listener, address, queued)
}

#[tokio::test]
async fn a_connect_that_stays_pending_over_ipv6_is_a_connect_timeout() {
    let (listener, address, queued) = blocked_listener().await;
    let request = Request::get("/echo").body(Body::empty()).unwrap();

    let outcome = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 1_024), request)
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ConnectTimeout);
    drop((listener, queued));
}

#[tokio::test]
async fn an_upstream_that_never_answers_is_a_response_timeout() {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    let request = Request::get("/echo").body(Body::empty()).unwrap();

    let outcome = forwarder(address)
        .forward(
            target_answering_within(UpstreamProtocol::Http1, 1_024, 100),
            request,
        )
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
    drop(listener);
}

#[tokio::test]
async fn the_upstream_receives_the_request_body_as_it_arrives() {
    let (received, mut arrived) = mpsc::unbounded_channel::<Bytes>();
    let router = Router::new().route(
        "/upload",
        post(move |body: Body| {
            let received = received.clone();
            async move {
                relay_chunks(body, &received).await;
                StatusCode::NO_CONTENT
            }
        }),
    );
    let address = serve(router).await;
    let (sender, outgoing) = chunked();
    let request = Request::post("/upload").body(outgoing).unwrap();
    let forwarding = tokio::spawn(async move {
        forwarder(address)
            .forward(target(UpstreamProtocol::Http1, 1_024), request)
            .await
    });

    sender.send(Bytes::from_static(b"first")).await.unwrap();
    let first = tokio::time::timeout(BOUND, arrived.recv()).await;
    assert_eq!(first.unwrap().unwrap(), Bytes::from_static(b"first"));
    sender.send(Bytes::from_static(b"second")).await.unwrap();
    drop(sender);

    let response = tokio::time::timeout(BOUND, forwarding)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_response_is_relayed_as_it_arrives() {
    let release = Arc::new(Notify::new());
    let gate = Arc::clone(&release);
    let router = Router::new().route(
        "/stream",
        get(move || {
            let gate = Arc::clone(&gate);
            async move {
                let (sender, chunks) = chunked();
                drop(tokio::spawn(async move {
                    sender.send(Bytes::from_static(b"head")).await.unwrap();
                    gate.notified().await;
                    sender.send(Bytes::from_static(b"tail")).await.unwrap();
                }));
                chunks
            }
        }),
    );
    let address = serve(router).await;
    let request = Request::get("/stream").body(Body::empty()).unwrap();

    let response = forwarder(address)
        .forward(target(UpstreamProtocol::Http1, 1_024), request)
        .await
        .unwrap();
    let mut body = response.into_body();
    let head = tokio::time::timeout(BOUND, body.frame()).await;
    release.notify_one();
    let tail = tokio::time::timeout(BOUND, body.frame()).await;

    assert_eq!(
        head.unwrap().unwrap().unwrap().into_data().unwrap(),
        Bytes::from_static(b"head")
    );
    assert_eq!(
        tail.unwrap().unwrap().unwrap().into_data().unwrap(),
        Bytes::from_static(b"tail")
    );
}

/// A body that yields the chunks sent through its channel and ends when the sender is dropped.
#[derive(Debug)]
struct ChunkedBody(mpsc::Receiver<Bytes>);

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(context)
            .map(|chunk| chunk.map(|bytes| Ok(Frame::data(bytes))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Sends every data frame of `body` to `received` as it arrives.
async fn relay_chunks(mut body: Body, received: &mpsc::UnboundedSender<Bytes>) {
    while let Some(Ok(frame)) = body.frame().await {
        if let Ok(chunk) = frame.into_data() {
            received.send(chunk).unwrap();
        }
    }
}

/// A body of unknown length and the sender that feeds it.
fn chunked() -> (mpsc::Sender<Bytes>, Body) {
    let (sender, receiver) = mpsc::channel(8);
    (sender, Body::new(ChunkedBody(receiver)))
}
