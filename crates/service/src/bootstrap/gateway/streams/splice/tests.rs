use hyper::server::conn::http1;
use iam_domain::HttpMethod;
use tokio::io::{AsyncReadExt as _, duplex};
use tokio::sync::oneshot;

use super::*;
use crate::bootstrap::gateway::streams::registry::{Grant, StreamRecord, StreamRegistry};

fn open(registry: &Arc<StreamRegistry>) -> Arc<StreamHandle> {
    let record = StreamRecord {
        subject: Some("user-1".to_owned()),
        session: Some("session-1".to_owned()),
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 1,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/ws".to_owned(),
    };
    Arc::new(registry.open(record, grant).unwrap())
}

#[test]
fn the_close_frame_carries_the_code_in_network_order() {
    assert_eq!(close_frame(1013), [0x88, 0x02, 0x03, 0xF5]);
    assert_eq!(close_frame(1008), [0x88, 0x02, 0x03, 0xF0]);
    assert_eq!(close_frame(1001), [0x88, 0x02, 0x03, 0xE9]);
}

#[tokio::test]
async fn bytes_flow_in_both_directions_unchanged() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let (mut browser, mut client) = duplex(1024);
    let (mut upstream, mut backend) = duplex(1024);
    let relaying = tokio::spawn(async move { relay(&mut client, &mut upstream, &handle).await });

    browser.write_all(b"\x81\x04ping").await.unwrap();
    let mut seen = [0_u8; 6];
    backend.read_exact(&mut seen).await.unwrap();
    backend.write_all(b"\x81\x04pong").await.unwrap();
    let mut answer = [0_u8; 6];
    browser.read_exact(&mut answer).await.unwrap();
    browser.shutdown().await.unwrap();
    backend.shutdown().await.unwrap();

    assert_eq!(&seen, b"\x81\x04ping");
    assert_eq!(&answer, b"\x81\x04pong");
    relaying.await.unwrap();
}

#[tokio::test]
async fn a_stream_the_registry_closes_gets_the_close_frame_of_its_reason() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let id = handle.id();
    let (mut browser, mut client) = duplex(1024);
    let (mut upstream, _backend) = duplex(1024);
    let relaying = tokio::spawn(async move { relay(&mut client, &mut upstream, &handle).await });

    registry.close(id, CloseReason::Fenced);

    let mut frame = [0_u8; 4];
    browser.read_exact(&mut frame).await.unwrap();
    let mut rest = Vec::new();
    browser.read_to_end(&mut rest).await.unwrap();
    assert_eq!(frame, close_frame(1013));
    assert_eq!(rest, Vec::<u8>::new());
    relaying.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn traffic_in_either_direction_counts_as_activity() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let (mut inbound, outbound) = duplex(1024);
    let (mut peer, other) = duplex(1024);
    let mut written = Tracked::new(outbound, Arc::clone(handle.activity()));
    let mut read = Tracked::new(other, Arc::clone(handle.activity()));

    tokio::time::advance(Duration::from_secs(30)).await;
    written.write_all(b"x").await.unwrap();
    written.flush().await.unwrap();
    assert_eq!(handle.activity().idle_for(), Duration::ZERO);
    tokio::time::advance(Duration::from_secs(20)).await;
    peer.write_all(b"y").await.unwrap();
    let mut byte = [0_u8; 1];
    read.read_exact(&mut byte).await.unwrap();

    assert_eq!(handle.activity().idle_for(), Duration::ZERO);
    let mut echoed = [0_u8; 1];
    inbound.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"x");
    written.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_goodbye_writes_the_frame_and_shuts_the_client_down() {
    let (mut browser, mut client) = duplex(64);

    goodbye(&mut client, CloseReason::Idle).await;

    let mut everything = Vec::new();
    browser.read_to_end(&mut everything).await.unwrap();
    assert_eq!(everything, close_frame(1001));
}

#[derive(Clone, Default)]
struct Written(Arc<std::sync::Mutex<Vec<u8>>>);

impl Written {
    fn text(&self) -> String {
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl io::Write for Written {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Written {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self {
        self.clone()
    }
}

fn debug_logs() -> (tracing::subscriber::DefaultGuard, Written) {
    let written = Written::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(written.clone())
        .finish();
    (tracing::subscriber::set_default(subscriber), written)
}

#[tokio::test]
async fn the_goodbye_and_the_end_of_a_stream_are_logged() {
    let (_guard, written) = debug_logs();
    let (mut browser, mut client) = duplex(64);

    goodbye(&mut client, CloseReason::Fenced).await;
    log_ended(&Ok((3, 4)));
    log_ended(&Err(io::Error::other("connection reset")));

    let text = written.text();
    assert!(text.contains("a WebSocket stream was closed"), "{text}");
    assert!(text.contains("delivered=true"), "{text}");
    assert!(text.contains("to_client=4"), "{text}");
    assert!(text.contains("connection reset"), "{text}");
    let mut everything = Vec::new();
    browser.read_to_end(&mut everything).await.unwrap();
    assert_eq!(everything, close_frame(1013));
}

#[tokio::test]
async fn upgrades_that_fail_end_the_relay_at_once() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let client = hyper::upgrade::on(axum::http::Request::new(()));
    let upstream = hyper::upgrade::on(axum::http::Response::new(()));

    run(Upgrades { client, upstream }, handle, ()).await;

    assert!(registry.is_empty());
}

#[tokio::test]
async fn the_goodbye_to_a_client_that_is_gone_is_not_delivered() {
    let (browser, mut client) = duplex(64);
    drop(browser);

    goodbye(&mut client, CloseReason::Fenced).await;
}

#[tokio::test(start_paused = true)]
async fn the_goodbye_to_a_client_that_does_not_read_gives_up_after_the_grace_period() {
    let (_browser, mut client) = duplex(1);

    goodbye(&mut client, CloseReason::Idle).await;
}

/// The upgrade of a connection that the handler answers with `101` when `switch` is set, and
/// never answers otherwise, and the raw end of that connection.
async fn upgrade_of(switch: bool) -> (OnUpgrade, tokio::io::DuplexStream) {
    let (mut peer, served) = duplex(4096);
    let (sender, receiver) = oneshot::channel();
    let sender = std::sync::Mutex::new(Some(sender));
    let service = hyper::service::service_fn(
        move |mut request: axum::http::Request<hyper::body::Incoming>| {
            let first = sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(sender) = first {
                drop(sender.send(hyper::upgrade::on(&mut request)));
            }
            async move {
                if !switch {
                    return std::future::pending().await;
                }
                Ok::<_, std::convert::Infallible>(
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "websocket")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
            }
        },
    );
    let connection = http1::Builder::new()
        .serve_connection(TokioIo::new(served), service)
        .with_upgrades();
    drop(tokio::spawn(connection));
    peer.write_all(
        b"GET /ws HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n",
    )
    .await
    .unwrap();
    let on_upgrade = receiver.await.unwrap();
    if switch {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(peer.read_u8().await.unwrap());
        }
    }
    (on_upgrade, peer)
}

#[tokio::test]
async fn a_stream_the_registry_closes_before_the_upgrades_complete_ends_the_relay() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let id = handle.id();
    let (client, _client_end) = upgrade_of(false).await;
    let (upstream, _upstream_end) = upgrade_of(false).await;
    let relaying = tokio::spawn(run(Upgrades { client, upstream }, handle, ()));

    registry.close(id, CloseReason::Idle);

    relaying.await.unwrap();
    assert!(registry.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_write_that_has_to_wait_is_not_traffic_until_it_completes() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let (_peer, outbound) = duplex(1);
    let mut written = Tracked::new(outbound, Arc::clone(handle.activity()));

    tokio::time::advance(Duration::from_secs(30)).await;
    let waited = tokio::time::timeout(Duration::from_secs(1), written.write_all(b"xyz")).await;

    assert!(waited.is_err());
}

#[tokio::test]
async fn upgraded_connections_relay_both_directions_until_both_sides_end() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let (client, mut browser) = upgrade_of(true).await;
    let (upstream, mut backend) = upgrade_of(true).await;
    let relaying = tokio::spawn(run(Upgrades { client, upstream }, handle, ()));

    browser.write_all(b"\x81\x04ping").await.unwrap();
    let mut seen = [0_u8; 6];
    backend.read_exact(&mut seen).await.unwrap();
    backend.write_all(b"\x81\x04pong").await.unwrap();
    let mut answer = [0_u8; 6];
    browser.read_exact(&mut answer).await.unwrap();
    browser.shutdown().await.unwrap();
    backend.shutdown().await.unwrap();

    relaying.await.unwrap();
    assert_eq!(&seen, b"\x81\x04ping");
    assert_eq!(&answer, b"\x81\x04pong");
    assert!(registry.is_empty());
}
