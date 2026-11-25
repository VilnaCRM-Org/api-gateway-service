//! The timeouts, retries, outlier ejection and concurrency limit of the `HyperUpstreamForwarder`
//! (Story 10.5) against real upstreams on loopback sockets.
//!
//! Endpoints are told apart by their zone: the gateway sits in `zone-a`, so a request goes to the
//! endpoint of `zone-a` first and a retry, which avoids the endpoint that failed, goes to the
//! endpoint of `zone-b`.

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
use axum::http::{Method, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt as _;
use hyper::body::{Body as HttpBody, Frame};
use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{
    EndpointConditions, EndpointParts, EndpointSlice, EnforcementMode, ForwardError, HttpMethod,
    RetryPolicy, RouteDraft, RouteFields, RouteFlag, RouteFlags, RouteId, UpstreamEndpoint,
    UpstreamForwarder as _, UpstreamId, UpstreamName, UpstreamProtocol, UpstreamSettings,
    UpstreamSettingsDraft, UpstreamTarget, WatchTarget, Zone,
};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use shared_domain::Uuid;
use test_support::rng::FakeRng;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

const BOUND: Duration = Duration::from_secs(10);
const OWN_ZONE: &str = "zone-a";
const OTHER_ZONE: &str = "zone-b";

fn service() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

/// An endpoint at `address` in `zone`.
fn endpoint(address: SocketAddr, zone: &str) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.ip().to_string(),
        port: address.port(),
        zone: Some(Zone::new(zone).unwrap()),
        pod: None,
        conditions: EndpointConditions::healthy(),
    })
}

/// A forwarder for a gateway in `zone-a` over `endpoints`.
fn forwarder_over(endpoints: Vec<UpstreamEndpoint>) -> HyperUpstreamForwarder {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: Some(Zone::new(OWN_ZONE).unwrap()),
    });
    directory.replace(
        &service(),
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints,
        }],
    );
    HyperUpstreamForwarder::new(directory.view(), true, Arc::new(FakeRng::seeded(3)))
}

/// What the route and the upstream of a request say.
#[derive(Debug, Clone, Copy)]
struct Shape {
    protocol: UpstreamProtocol,
    retry: RetryPolicy,
    graphql: bool,
    concurrency_limit: i64,
    request_timeout_ms: i64,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            protocol: UpstreamProtocol::Http1,
            retry: RetryPolicy::None,
            graphql: false,
            concurrency_limit: 100,
            request_timeout_ms: 60_000,
        }
    }
}

fn target(shape: Shape) -> UpstreamTarget {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol: shape.protocol,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms: 10_000,
        concurrency_limit: shape.concurrency_limit,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();
    let route = RouteFields::new(&RouteDraft {
        host: "api.example.test".to_owned(),
        methods: vec![HttpMethod::Get, HttpMethod::Post, HttpMethod::Put],
        path_pattern: "/x".to_owned(),
        service: "core".to_owned(),
        upstream_id: UpstreamId::from_uuid(
            Uuid::parse("00000000-0000-0000-0000-000000000002").unwrap(),
        ),
        flags: RouteFlags::NONE.with(RouteFlag::Graphql, shape.graphql),
        enforcement: EnforcementMode::Enforce,
        body_limit: 10 * 1024 * 1024,
        request_timeout_ms: shape.request_timeout_ms,
        idle_timeout_ms: 60_000,
        retry: shape.retry,
        rate_policies: Vec::new(),
        cors: None,
    })
    .unwrap();
    UpstreamTarget::new(
        UpstreamName::new("user-service").unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    )
    .with_settings(&settings)
    .with_route(&route)
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake upstream on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// What a fake upstream saw.
#[derive(Debug, Clone, Default)]
struct Hits(Arc<AtomicUsize>);

impl Hits {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// An upstream that answers every request with `status` and counts them.
async fn answering(status: StatusCode) -> (SocketAddr, Hits) {
    let hits = Hits::default();
    let router = Router::new()
        .fallback(async move |State(hits): State<Hits>| {
            hits.0.fetch_add(1, Ordering::SeqCst);
            status
        })
        .with_state(hits.clone());
    (serve(router).await, hits)
}

async fn serve(router: Router) -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    address
}

/// An address that refuses connections.
async fn refusing() -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

/// An upstream that reads the request and closes the connection without answering.
async fn resetting() -> (SocketAddr, Hits) {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    let hits = Hits::default();
    let counted = hits.clone();
    drop(tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            counted.0.fetch_add(1, Ordering::SeqCst);
            read_some(&stream).await;
            drop(stream);
        }
    }));
    (address, hits)
}

async fn read_some(stream: &TcpStream) {
    let mut buffer = [0_u8; 4096];
    stream.readable().await.unwrap();
    drop(stream.try_read(&mut buffer));
}

/// A response body that sends one chunk and then stalls for good.
#[derive(Debug, Default)]
struct Stalled {
    sent: bool,
}

impl HttpBody for Stalled {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.sent {
            return Poll::Pending;
        }
        self.sent = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"start")))))
    }
}

async fn stalling() -> Response {
    Response::new(Body::new(Stalled::default()))
}

/// An HTTP/2 upstream that refuses the first stream of every connection with `REFUSED_STREAM`,
/// which says that it processed none of the request. The frames are written by hand.
async fn refusing_streams() -> (SocketAddr, Hits) {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    let hits = Hits::default();
    let counted = hits.clone();
    drop(tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            counted.0.fetch_add(1, Ordering::SeqCst);
            drop(tokio::spawn(refuse_streams_of(stream)));
        }
    }));
    (address, hits)
}

/// Answers the HTTP/2 handshake of `stream` and resets every stream that opens.
async fn refuse_streams_of(mut stream: TcpStream) {
    const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];
    const SETTINGS_ACK: [u8; 9] = [0, 0, 0, 4, 1, 0, 0, 0, 0];
    let mut preface = [0_u8; 24];
    if stream.read_exact(&mut preface).await.is_err()
        || stream.write_all(&EMPTY_SETTINGS).await.is_err()
    {
        return;
    }
    let mut head = [0_u8; 9];
    while stream.read_exact(&mut head).await.is_ok() {
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]);
        let mut payload = vec![0_u8; usize::try_from(length).unwrap()];
        if stream.read_exact(&mut payload).await.is_err() {
            return;
        }
        let reply: Vec<u8> = match (head[3], head[4] & 1) {
            (4, 0) => SETTINGS_ACK.to_vec(),
            (1, _) => [&[0, 0, 4, 3, 0][..], &head[5..9], &7_u32.to_be_bytes()[..]].concat(),
            _ => continue,
        };
        if stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}

fn request(method: Method, body: Body) -> Request {
    Request::builder()
        .method(method)
        .uri("/x")
        .body(body)
        .unwrap()
}

fn get() -> Request {
    request(Method::GET, Body::empty())
}

#[tokio::test(start_paused = true)]
async fn an_upstream_that_never_sends_headers_is_cut_off_after_ten_seconds_for_rest() {
    let silent = bound().await;
    let forwarder = forwarder_over(vec![endpoint(silent.local_addr().unwrap(), OWN_ZONE)]);
    let started = Instant::now();

    let outcome = forwarder.forward(target(Shape::default()), get()).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
    assert_eq!(started.elapsed().as_secs(), 10);
    drop(silent);
}

#[tokio::test(start_paused = true)]
async fn the_same_silence_lasts_thirty_seconds_on_a_graphql_route() {
    let silent = bound().await;
    let forwarder = forwarder_over(vec![endpoint(silent.local_addr().unwrap(), OWN_ZONE)]);
    let shape = Shape {
        graphql: true,
        ..Shape::default()
    };
    let started = Instant::now();

    let outcome = forwarder
        .forward(target(shape), request(Method::POST, Body::from("{}")))
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
    assert_eq!(started.elapsed().as_secs(), 30);
    drop(silent);
}

#[tokio::test(start_paused = true)]
async fn the_request_timeout_of_a_route_shortens_the_rest_limit() {
    let silent = bound().await;
    let forwarder = forwarder_over(vec![endpoint(silent.local_addr().unwrap(), OWN_ZONE)]);
    let shape = Shape {
        request_timeout_ms: 2_000,
        ..Shape::default()
    };
    let started = Instant::now();

    let outcome = forwarder.forward(target(shape), get()).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
    assert_eq!(started.elapsed().as_secs(), 2);
    drop(silent);
}

#[tokio::test]
async fn a_post_whose_connection_was_refused_is_sent_once_more_to_another_endpoint() {
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![
        endpoint(refusing().await, OWN_ZONE),
        endpoint(good, OTHER_ZONE),
    ]);

    let response = forwarder
        .forward(
            target(Shape::default()),
            request(Method::POST, Body::from("a body")),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hits.count(), 1);
}

#[tokio::test]
async fn a_get_that_was_reset_after_it_was_written_is_retried_on_an_idempotent_route() {
    let (broken, reset_hits) = resetting().await;
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![endpoint(broken, OWN_ZONE), endpoint(good, OTHER_ZONE)]);
    let shape = Shape {
        retry: RetryPolicy::Idempotent,
        ..Shape::default()
    };

    let response = forwarder.forward(target(shape), get()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(reset_hits.count(), 1);
    assert_eq!(hits.count(), 1);
}

#[tokio::test]
async fn a_get_that_was_reset_is_not_retried_on_a_route_without_a_retry_policy() {
    let (broken, _reset_hits) = resetting().await;
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![endpoint(broken, OWN_ZONE), endpoint(good, OTHER_ZONE)]);

    let outcome = forwarder.forward(target(Shape::default()), get()).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::Upstream);
    assert_eq!(hits.count(), 0);
}

#[tokio::test]
async fn a_graphql_mutation_that_was_reset_is_never_retried() {
    let (broken, _reset_hits) = resetting().await;
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![endpoint(broken, OWN_ZONE), endpoint(good, OTHER_ZONE)]);
    let shape = Shape {
        retry: RetryPolicy::Idempotent,
        graphql: true,
        ..Shape::default()
    };
    let mutation = request(
        Method::POST,
        Body::from(r#"{"query":"mutation { createUser }"}"#),
    );

    let outcome = forwarder.forward(target(shape), mutation).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::Upstream);
    assert_eq!(hits.count(), 0);
}

#[tokio::test]
async fn a_put_with_a_streamed_body_is_not_retried_and_one_with_a_small_body_is() {
    let shape = Shape {
        retry: RetryPolicy::Idempotent,
        ..Shape::default()
    };
    let streamed = {
        let (broken, _reset_hits) = resetting().await;
        let (good, hits) = answering(StatusCode::OK).await;
        let forwarder =
            forwarder_over(vec![endpoint(broken, OWN_ZONE), endpoint(good, OTHER_ZONE)]);
        let megabyte = request(Method::PUT, Body::from(vec![7_u8; 1024 * 1024]));
        (forwarder.forward(target(shape), megabyte).await, hits)
    };
    let buffered = {
        let (broken, _reset_hits) = resetting().await;
        let (good, hits) = answering(StatusCode::OK).await;
        let forwarder =
            forwarder_over(vec![endpoint(broken, OWN_ZONE), endpoint(good, OTHER_ZONE)]);
        let small = request(Method::PUT, Body::from(vec![7_u8; 4 * 1024]));
        (forwarder.forward(target(shape), small).await, hits)
    };

    assert_eq!(streamed.0.unwrap_err(), ForwardError::Upstream);
    assert_eq!(streamed.1.count(), 0);
    assert_eq!(buffered.0.unwrap().status(), StatusCode::OK);
    assert_eq!(buffered.1.count(), 1);
}

#[tokio::test]
async fn a_retry_above_the_budget_of_the_upstream_is_not_made() {
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![
        endpoint(refusing().await, OWN_ZONE),
        endpoint(good, OTHER_ZONE),
    ]);

    let first = forwarder.forward(target(Shape::default()), get()).await;
    let second = forwarder.forward(target(Shape::default()), get()).await;

    assert_eq!(first.unwrap().status(), StatusCode::OK);
    assert_eq!(second.unwrap_err(), ForwardError::NotSent);
    assert_eq!(hits.count(), 1);
}

#[tokio::test]
async fn an_endpoint_with_five_consecutive_server_errors_receives_nothing_more() {
    let (failing, failing_hits) = answering(StatusCode::INTERNAL_SERVER_ERROR).await;
    let (good, good_hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![
        endpoint(failing, OWN_ZONE),
        endpoint(good, OTHER_ZONE),
    ]);

    let mut statuses = Vec::new();
    for _ in 0..8 {
        let response = forwarder.forward(target(Shape::default()), get()).await;
        statuses.push(response.unwrap().status());
    }

    assert_eq!(failing_hits.count(), 5);
    assert_eq!(good_hits.count(), 3);
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.is_server_error())
            .count(),
        5
    );
}

#[tokio::test]
async fn with_four_of_six_endpoints_failing_no_more_than_three_are_ejected() {
    let mut failing = Vec::new();
    let mut endpoints = Vec::new();
    for _ in 0..4 {
        let (address, hits) = answering(StatusCode::INTERNAL_SERVER_ERROR).await;
        endpoints.push(endpoint(address, OWN_ZONE));
        failing.push(hits);
    }
    for _ in 0..2 {
        let (address, _hits) = answering(StatusCode::OK).await;
        endpoints.push(endpoint(address, OWN_ZONE));
    }
    let forwarder = forwarder_over(endpoints);

    for _ in 0..300 {
        drop(forwarder.forward(target(Shape::default()), get()).await);
    }

    let counts: Vec<usize> = failing.iter().map(Hits::count).collect();
    let ejected = counts.iter().filter(|hits| **hits == 5).count();
    assert!(ejected <= 3);
    assert!(counts.iter().any(|hits| *hits > 5));
}

/// An upstream that holds each request until released.
async fn holding() -> (SocketAddr, Hits, Arc<Semaphore>) {
    let hits = Hits::default();
    let release = Arc::new(Semaphore::new(0));
    let gate = Arc::clone(&release);
    let counted = hits.clone();
    let router = Router::new().fallback(move || {
        let gate = Arc::clone(&gate);
        let counted = counted.clone();
        async move {
            counted.0.fetch_add(1, Ordering::SeqCst);
            gate.acquire().await.unwrap().forget();
            Response::new(Body::from("done"))
        }
    });
    (serve(router).await, hits, release)
}

#[tokio::test]
async fn a_request_above_the_concurrency_limit_is_refused_at_once() {
    let (address, hits, release) = holding().await;
    let forwarder = Arc::new(forwarder_over(vec![endpoint(address, OWN_ZONE)]));
    let shape = Shape {
        concurrency_limit: 2,
        ..Shape::default()
    };
    let mut held = Vec::new();
    for _ in 0..2 {
        let forwarder = Arc::clone(&forwarder);
        held.push(tokio::spawn(async move {
            forwarder.forward(target(shape), get()).await
        }));
    }
    while hits.count() < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let third = tokio::time::timeout(BOUND, forwarder.forward(target(shape), get())).await;

    assert_eq!(third.unwrap().unwrap_err(), ForwardError::Overloaded);
    assert_eq!(hits.count(), 2);
    release.add_permits(2);
    for task in held {
        let response = tokio::time::timeout(BOUND, task).await.unwrap().unwrap();
        let body = response.unwrap().into_body().collect().await.unwrap();
        assert_eq!(body.to_bytes(), Bytes::from_static(b"done"));
    }
}

#[tokio::test]
async fn the_place_of_a_request_is_free_again_once_its_response_ended() {
    let (address, _hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![endpoint(address, OWN_ZONE)]);
    let shape = Shape {
        concurrency_limit: 1,
        ..Shape::default()
    };

    for _ in 0..3 {
        let response = forwarder.forward(target(shape), get()).await.unwrap();
        drop(response.into_body().collect().await.unwrap());
    }
}

#[tokio::test]
async fn a_get_on_a_stream_that_the_server_refused_is_sent_once_more_to_another_endpoint() {
    let (strict, refusals) = refusing_streams().await;
    let (good, hits) = answering(StatusCode::OK).await;
    let forwarder = forwarder_over(vec![endpoint(strict, OWN_ZONE), endpoint(good, OTHER_ZONE)]);
    let shape = Shape {
        protocol: UpstreamProtocol::H2c,
        ..Shape::default()
    };

    let response = forwarder.forward(target(shape), get()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(refusals.count(), 1);
    assert_eq!(hits.count(), 1);
}

#[tokio::test]
async fn the_request_timeout_ends_a_response_body_that_stalls_after_its_first_chunk() {
    let address = serve(Router::new().fallback(stalling)).await;
    let forwarder = forwarder_over(vec![endpoint(address, OWN_ZONE)]);
    let shape = Shape {
        request_timeout_ms: 1_000,
        ..Shape::default()
    };

    let response = forwarder.forward(target(shape), get()).await.unwrap();
    let mut body = response.into_body();

    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first, Bytes::from_static(b"start"));
    assert!(body.frame().await.unwrap().is_err());
}

#[tokio::test]
async fn the_relayed_body_reports_the_length_and_the_end_that_the_upstream_declared() {
    let address = serve(Router::new().fallback(async || "hello")).await;
    let forwarder = forwarder_over(vec![endpoint(address, OWN_ZONE)]);

    let response = forwarder
        .forward(target(Shape::default()), get())
        .await
        .unwrap();
    let body = response.into_body();

    assert_eq!(body.size_hint().exact(), Some(5));
    assert!(!body.is_end_stream());
}
