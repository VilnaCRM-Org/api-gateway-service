use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::routing::get;
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper::{Request, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use test_support::log::LogRecorder;

use super::{BoxError, ConnectionSignals, log_ended, serve};

const LIMIT: Duration = Duration::from_secs(5);

struct Rig {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    shed: watch::Sender<bool>,
    server: JoinHandle<io::Result<()>>,
}

async fn ok() -> &'static str {
    "ok"
}

#[expect(
    clippy::disallowed_methods,
    reason = "a test serves the gateway on a free loopback port"
)]
async fn start() -> Rig {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = watch::channel(false);
    let (shed, shedding) = watch::channel(false);
    let router = Router::new().route("/", get(ok));
    let server = tokio::spawn(serve(
        listener,
        router,
        ConnectionSignals { stopping, shedding },
    ));
    Rig {
        address,
        stop,
        shed,
        server,
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "a test connects to its own gateway on loopback"
)]
async fn connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

fn request() -> Request<Empty<Bytes>> {
    Request::get("/")
        .header("host", "gateway")
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

#[tokio::test]
async fn a_pod_that_does_not_shed_keeps_its_http1_connections_alive() {
    let rig = start().await;
    let (mut sender, _ended) = h1(rig.address).await;

    for _ in 0..2 {
        sender.ready().await.unwrap();
        let response = sender.send_request(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("connection").is_none());
        response.into_body().collect().await.unwrap();
    }
}

#[tokio::test]
async fn a_pod_that_sheds_sends_connection_close_on_the_next_http1_response() {
    let rig = start().await;
    let (mut sender, ended) = h1(rig.address).await;
    sender.ready().await.unwrap();
    sender
        .send_request(request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    rig.shed.send_replace(true);
    sender.ready().await.unwrap();
    let response = sender.send_request(request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("connection").unwrap(), "close");
    response.into_body().collect().await.unwrap();
    timeout(LIMIT, ended).await.unwrap().unwrap();
    assert!(sender.ready().await.is_err());
}

#[tokio::test]
async fn a_pod_that_sheds_sends_goaway_on_its_http2_connections() {
    let rig = start().await;
    let (mut sender, ended) = h2(rig.address).await;
    sender.ready().await.unwrap();
    let response = sender.send_request(request()).await.unwrap();
    assert_eq!(response.version(), Version::HTTP_2);
    response.into_body().collect().await.unwrap();

    rig.shed.send_replace(true);

    timeout(LIMIT, ended).await.unwrap().unwrap();
    assert!(sender.ready().await.is_err());
}

#[tokio::test]
async fn an_http2_connection_that_arrives_while_the_pod_sheds_is_served_and_then_told_to_leave() {
    let rig = start().await;
    rig.shed.send_replace(true);
    let (mut sender, ended) = h2(rig.address).await;

    sender.ready().await.unwrap();
    let response = sender.send_request(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();

    timeout(LIMIT, ended).await.unwrap().unwrap();
}

#[tokio::test]
async fn a_pod_that_stops_shuts_every_connection_down_and_returns() {
    let rig = start().await;
    let (mut first, first_ended) = h1(rig.address).await;
    let (mut second, second_ended) = h2(rig.address).await;
    first.ready().await.unwrap();
    first
        .send_request(request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    second.ready().await.unwrap();
    second
        .send_request(request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    rig.stop.send_replace(true);

    timeout(LIMIT, rig.server).await.unwrap().unwrap().unwrap();
    timeout(LIMIT, first_ended).await.unwrap().unwrap();
    timeout(LIMIT, second_ended).await.unwrap().unwrap();
}

#[tokio::test]
async fn signals_without_a_shedding_flag_never_shed() {
    let (stop, stopping) = watch::channel(false);
    let signals = ConnectionSignals::new(stopping, None);

    assert!(!*signals.shedding.borrow());
    assert!(!*signals.stopping.borrow());
    stop.send_replace(true);
    assert!(*signals.stopping.borrow());
}

#[tokio::test]
async fn signals_over_a_shedding_flag_follow_it() {
    let (_stop, stopping) = watch::channel(false);
    let (shed, shedding) = watch::channel(false);
    let signals = ConnectionSignals::new(stopping, Some(shedding));

    shed.send_replace(true);

    assert!(*signals.shedding.borrow());
}

#[test]
fn a_connection_that_ends_with_an_error_is_logged_and_one_that_ends_well_is_not() {
    let failed: Result<(), BoxError> = Err(Box::new(io::Error::other("reset by peer")));
    let (recorder, guard) = LogRecorder::install();

    log_ended(&Ok(()));
    log_ended(&failed);
    drop(guard);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "a connection ended with an error");
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "a test serves the gateway on a free loopback port"
)]
async fn a_server_without_a_shedding_flag_serves_until_it_stops() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = watch::channel(false);
    let router = Router::new().route("/", get(ok));
    let server = tokio::spawn(serve(
        listener,
        router,
        ConnectionSignals::new(stopping, None),
    ));
    let (mut sender, ended) = h1(address).await;
    sender.ready().await.unwrap();

    let response = sender.send_request(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("connection").is_none());
    response.into_body().collect().await.unwrap();
    stop.send_replace(true);

    timeout(LIMIT, server).await.unwrap().unwrap().unwrap();
    timeout(LIMIT, ended).await.unwrap().unwrap();
}
