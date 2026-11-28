use axum::http::header::CONTENT_TYPE;
use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{
    EndpointConditions, EndpointParts, EndpointSlice, HttpMethod, RouteId, UpstreamEndpoint,
    UpstreamForwarder as _, UpstreamName, UpstreamProtocol, UpstreamSettings,
    UpstreamSettingsDraft, WatchTarget,
};
use rstest::rstest;
use shared_domain::Uuid;
use test_support::rng::FakeRng;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;
use crate::bootstrap::gateway::streams::{Grant, StreamRecord, StreamRegistry};

fn handle(registry: &Arc<StreamRegistry>) -> Arc<StreamHandle> {
    let record = StreamRecord {
        subject: Some("user-1".to_owned()),
        session: Some("session-1".to_owned()),
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 1,
        route: None,
        service: None,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/ws".to_owned(),
    };
    Arc::new(registry.open(record, grant).unwrap())
}

fn target() -> UpstreamTarget {
    UpstreamTarget::new(
        UpstreamName::new("user-service").unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    )
}

fn forwarder() -> HyperUpstreamForwarder {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    HyperUpstreamForwarder::new(directory.view(), true, Arc::new(FakeRng::seeded(7)))
}

fn upgrade_request(upgrade: &str, stream: Option<Arc<StreamHandle>>) -> Request {
    let mut request = Request::builder()
        .uri("/ws")
        .header("connection", "keep-alive, Upgrade, X-Hop")
        .header("upgrade", upgrade)
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .header("x-hop", "1")
        .header("te", "trailers")
        .body(Body::empty())
        .unwrap();
    if let Some(stream) = stream {
        request.extensions_mut().insert(stream);
    }
    request
}

#[rstest]
#[case("websocket", true, Version::HTTP_11, true)]
#[case("WebSocket", true, Version::HTTP_11, true)]
#[case("h2c", true, Version::HTTP_11, false)]
#[case("websocket", false, Version::HTTP_11, false)]
#[case("websocket", true, Version::HTTP_2, false)]
fn only_a_websocket_upgrade_of_a_registered_stream_over_http1_opens_a_websocket(
    #[case] upgrade: &str,
    #[case] registered: bool,
    #[case] version: Version,
    #[case] expected: bool,
) {
    let registry = StreamRegistry::new(4);
    let stream = registered.then(|| handle(&registry));
    let mut request = upgrade_request(upgrade, stream);
    *request.version_mut() = version;

    assert_eq!(opens_websocket(&request), expected);
}

#[test]
fn a_request_without_an_upgrade_header_opens_no_websocket() {
    let registry = StreamRegistry::new(4);
    let mut request = Request::builder()
        .uri("/events")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(handle(&registry));

    assert!(!opens_websocket(&request));
}

#[test]
fn the_upgrade_request_keeps_the_handshake_and_drops_the_other_hop_by_hop_headers() {
    let (parts, _body) = upgrade_request("websocket", None).into_parts();

    let template = upgrade_template(parts);

    assert_eq!(template.version, Version::HTTP_11);
    assert_eq!(template.headers.get(UPGRADE).unwrap(), "websocket");
    assert_eq!(template.headers.get(CONNECTION).unwrap(), "upgrade");
    assert_eq!(
        template.headers.get("sec-websocket-key").unwrap(),
        "dGhlIHNhbXBsZSBub25jZQ=="
    );
    assert_eq!(template.headers.get("sec-websocket-version").unwrap(), "13");
    assert!(template.headers.get("x-hop").is_none());
    assert!(template.headers.get("te").is_none());
}

#[test]
fn an_event_stream_stays_under_the_registration_of_its_stream() {
    let registry = StreamRegistry::new(4);
    let mut response = Response::new(Body::from("data: x\n\n"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));

    let kept = guarded(response, Some(handle(&registry)));

    assert_eq!(registry.len(), 1);
    drop(kept);
    assert!(registry.is_empty());
}

#[test]
fn any_other_response_of_a_registered_stream_gives_up_its_registration() {
    let registry = StreamRegistry::new(4);
    let mut response = Response::new(Body::from("{}"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let plain = guarded(response, Some(handle(&registry)));

    assert!(registry.is_empty());
    assert_eq!(plain.status(), StatusCode::OK);
}

#[test]
fn a_response_of_a_request_without_a_registration_is_returned_as_it_is() {
    let response = guarded(Response::new(Body::empty()), None);

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_upgrade_without_the_registration_of_its_stream_is_not_sent() {
    let outcome = forwarder()
        .forward_upgrade(target(), upgrade_request("websocket", None))
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NotSent);
}

#[tokio::test]
async fn an_upgrade_to_a_service_without_endpoints_is_refused_before_anything_is_sent() {
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let outcome = forwarder().forward(target(), request).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
    assert!(registry.is_empty());
}

fn target_answering_within(response_timeout_ms: i64) -> UpstreamTarget {
    target_limited_to(response_timeout_ms, 100)
}

fn target_limited_to(response_timeout_ms: i64, concurrency_limit: i64) -> UpstreamTarget {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::Http1,
        forward_credentials: false,
        connect_timeout_ms: 1_000,
        response_timeout_ms,
        concurrency_limit,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();
    target().with_settings(&settings)
}

fn forwarder_at(address: std::net::SocketAddr) -> HyperUpstreamForwarder {
    forwarder_to(&address.ip().to_string(), address.port())
}

fn forwarder_to(host: &str, port: u16) -> HyperUpstreamForwarder {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    directory.replace(
        &WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "user-service".to_owned(),
        },
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints: vec![UpstreamEndpoint::new(EndpointParts {
                address: host.to_owned(),
                port,
                zone: None,
                pod: None,
                conditions: EndpointConditions::healthy(),
            })],
        }],
    );
    HyperUpstreamForwarder::new(directory.view(), true, Arc::new(FakeRng::seeded(7)))
}

#[expect(
    clippy::disallowed_methods,
    reason = "a unit test serves one scripted answer on a free loopback port"
)]
async fn loopback_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Accepts one connection, reads the request head and answers `reply`, or never answers when
/// `reply` is `None`. An answer that switches protocols keeps the connection open.
fn script(listener: TcpListener, reply: Option<&'static [u8]>) {
    drop(tokio::spawn(async move {
        let (mut socket, _peer) = listener.accept().await.unwrap();
        let mut head = [0_u8; 2048];
        drop(socket.read(&mut head).await);
        match reply {
            Some(reply) => {
                socket.write_all(reply).await.unwrap();
                if reply.starts_with(b"HTTP/1.1 101") {
                    std::future::pending::<()>().await;
                }
                socket.shutdown().await.unwrap();
            }
            None => std::future::pending::<()>().await,
        }
    }));
}

#[tokio::test]
async fn an_upstream_that_does_not_switch_protocols_gives_its_plain_answer() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    script(
        listener,
        Some(b"HTTP/1.1 426 Upgrade Required\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"),
    );
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let answered = forward_upgrade(
        &forwarder_at(address),
        target_answering_within(10_000),
        request,
    )
    .await
    .unwrap();

    assert_eq!(answered.status(), StatusCode::UPGRADE_REQUIRED);
    drop(answered);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn an_upstream_that_refuses_the_connection_leaves_the_upgrade_unsent() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    drop(listener);
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let outcome = forward_upgrade(
        &forwarder_at(address),
        target_answering_within(10_000),
        request,
    )
    .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NotSent);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn an_upstream_that_never_answers_the_upgrade_ends_with_the_response_timeout() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    script(listener, None);
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let outcome = forward_upgrade(
        &forwarder_at(address),
        target_answering_within(200),
        request,
    )
    .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn an_upgrade_to_an_upstream_at_its_concurrency_limit_is_refused() {
    let forwarder = forwarder_to("127.0.0.1", 9);
    let limited = target_limited_to(10_000, 1);
    let _held = forwarder.registry.admit(&limited).unwrap();
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let outcome = forward_upgrade(&forwarder, limited, request).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::Overloaded);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn an_endpoint_without_a_valid_address_is_refused_before_the_upgrade_is_sent() {
    let forwarder = forwarder_to("not an address", 80);
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let outcome = forward_upgrade(&forwarder, target_answering_within(10_000), request).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
    assert!(registry.is_empty());
}

#[test]
fn a_template_of_a_request_without_an_upgrade_header_adds_none() {
    let (parts, _body) = Request::builder()
        .uri("/ws")
        .body(Body::empty())
        .unwrap()
        .into_parts();

    let template = upgrade_template(parts);

    assert!(template.headers.get(UPGRADE).is_none());
    assert_eq!(template.headers.get(CONNECTION).unwrap(), "upgrade");
}

#[tokio::test]
async fn an_upstream_that_switches_protocols_gets_its_101_back_and_a_relay_for_the_stream() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    script(
        listener,
        Some(b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n"),
    );
    let registry = StreamRegistry::new(4);
    let request = upgrade_request("websocket", Some(handle(&registry)));

    let answered = forward_upgrade(
        &forwarder_at(address),
        target_answering_within(10_000),
        request,
    )
    .await
    .unwrap();

    assert_eq!(answered.status(), StatusCode::SWITCHING_PROTOCOLS);
}
