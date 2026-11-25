//! The pipeline with the production [`HyperUpstreamForwarder`] against fake upstreams on loopback
//! sockets (Story 10.3): the response is relayed unchanged, and a body above the limit of the
//! route, a refused connection and a connect that never completes are answered 413, 502 and 504.
//! No database is involved: the decision and the forwarding come from the snapshot alone.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use http_body_util::BodyExt as _;
use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{EndpointConditions, EndpointParts, EndpointSlice, UpstreamEndpoint, WatchTarget};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use test_support::gateway_snapshot::CountingPolicyView;
use test_support::rng::FakeRng;
use test_support::seed::TestRng;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tower::ServiceExt as _;

use super::{GOOD, HOST, pipeline_over, snapshot};

/// The route limit of the fixtures: 1 MiB.
const LIMIT: usize = 1_048_576;

/// The pipeline over a snapshot whose upstream `users` has one endpoint at `address`.
fn proxy_to(address: SocketAddr) -> Router {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "platform".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    directory.replace(
        &WatchTarget {
            namespace: "platform".to_owned(),
            service: "users-service".to_owned(),
        },
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
    let forwarder = Arc::new(HyperUpstreamForwarder::new(
        directory.view(),
        true,
        Arc::new(FakeRng::seeded(1)),
    ));
    let mut rng = TestRng::from_env();
    let view = Arc::new(CountingPolicyView::serving(snapshot(&mut rng, true)));
    pipeline_over(&view, forwarder, None).0
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake upstream on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// What the fake upstream saw: the number of requests that reached it.
#[derive(Debug, Clone, Default)]
struct Seen(Arc<AtomicUsize>);

async fn answer(State(seen): State<Seen>, body: Bytes) -> Response {
    seen.0.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::CREATED,
        [("x-upstream", "yes")],
        format!("upstream got {} bytes", body.len()),
    )
        .into_response()
}

/// Serves a fake upstream and returns its address with the counter of the requests it saw.
async fn upstream_answering() -> (SocketAddr, Seen) {
    let seen = Seen::default();
    let router = Router::new()
        .route("/api/users/{id}", get(answer))
        .with_state(seen.clone());
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    (address, seen)
}

fn request(body: Body, length: Option<usize>) -> Request<Body> {
    let mut builder = Request::get("/api/users/42")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"));
    if let Some(length) = length {
        builder = builder.header(CONTENT_LENGTH, length);
    }
    builder.body(body).unwrap()
}

async fn text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn the_response_of_the_upstream_is_relayed_unchanged() {
    let (address, seen) = upstream_answering().await;

    let response = proxy_to(address)
        .oneshot(request(Body::from("hello"), Some(5)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-upstream"], "yes");
    assert_eq!(text(response).await, "upstream got 5 bytes");
    assert_eq!(seen.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_body_declared_above_the_limit_is_a_413_and_the_upstream_sees_nothing() {
    let (address, seen) = upstream_answering().await;

    let response = proxy_to(address)
        .oneshot(request(Body::from(vec![0_u8; LIMIT + 1]), Some(LIMIT + 1)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(seen.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_body_above_the_limit_without_a_declared_length_is_a_413() {
    let (address, _seen) = upstream_answering().await;

    let response = proxy_to(address)
        .oneshot(request(Body::from(vec![0_u8; LIMIT + 1]), None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_refused_connection_is_a_502() {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(listener);

    let response = proxy_to(address)
        .oneshot(request(Body::empty(), None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

/// A listener on `[::1]` whose queue of connections is full and that never accepts: a connect to
/// it stays pending until the streams drop.
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
async fn a_connect_that_never_completes_is_a_504() {
    let (listener, address, queued) = blocked_listener().await;

    let response = proxy_to(address)
        .oneshot(request(Body::empty(), None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    drop((listener, queued));
}
