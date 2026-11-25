use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::post;
use iam_infrastructure::LokiTransport as _;
use tokio::net::TcpListener;

use super::HyperLokiTransport;

type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

#[derive(Clone)]
struct Stub {
    status: StatusCode,
    seen: Seen,
}

async fn receive(State(stub): State<Stub>, headers: HeaderMap, body: String) -> StatusCode {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    stub.seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((header("x-scope-orgid"), header("content-type"), body));
    stub.status
}

#[expect(
    clippy::disallowed_methods,
    reason = "a unit test serves its stub of Loki on a free loopback port"
)]
async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Serves a Loki stub that answers `status`; returns its push URL and what it received.
async fn serve(status: StatusCode) -> (Uri, Seen) {
    let seen = Seen::default();
    let listener = bind().await;
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/loki/api/v1/push", post(receive))
        .with_state(Stub {
            status,
            seen: Arc::clone(&seen),
        });
    tokio::spawn(async move { axum::serve(listener, app).await });
    let uri = format!("http://{address}/loki/api/v1/push")
        .parse()
        .unwrap();
    (uri, seen)
}

/// Pushes `body` from a plain thread, as the sink does.
fn push_from_a_thread(transport: HyperLokiTransport, body: &'static str) -> bool {
    std::thread::spawn(move || transport.push(body))
        .join()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_success_answer_acknowledges_and_the_push_carries_the_tenant_and_the_json() {
    let (uri, seen) = serve(StatusCode::NO_CONTENT).await;
    let transport = HyperLokiTransport::new(uri, "tenant-7").unwrap();

    let acknowledged = push_from_a_thread(transport, "{\"streams\":[]}");

    assert!(acknowledged);
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        seen.as_slice(),
        [(
            "tenant-7".to_owned(),
            "application/json".to_owned(),
            "{\"streams\":[]}".to_owned()
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_error_status_does_not_acknowledge() {
    let (uri, seen) = serve(StatusCode::SERVICE_UNAVAILABLE).await;
    let transport = HyperLokiTransport::new(uri, "tenant-7").unwrap();

    let acknowledged = push_from_a_thread(transport, "{}");

    assert!(!acknowledged);
    assert_eq!(seen.lock().unwrap_or_else(PoisonError::into_inner).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connection_does_not_acknowledge() {
    let listener = bind().await;
    let address = listener.local_addr().unwrap();
    drop(listener);
    let uri = format!("http://{address}/loki/api/v1/push")
        .parse()
        .unwrap();
    let transport = HyperLokiTransport::new(uri, "tenant-7").unwrap();

    assert!(!push_from_a_thread(transport, "{}"));
}

#[test]
fn a_tenant_that_cannot_be_a_header_value_is_refused() {
    let uri: Uri = "http://localhost:3100/loki/api/v1/push".parse().unwrap();

    let error = HyperLokiTransport::new(uri, "bad\ntenant").unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn the_debug_form_names_the_endpoint_and_nothing_else() {
    let uri: Uri = "http://loki:3100/loki/api/v1/push".parse().unwrap();
    let transport = HyperLokiTransport::new(uri, "tenant-7").unwrap();

    let shown = format!("{transport:?}");

    assert!(shown.contains("http://loki:3100/loki/api/v1/push"));
    assert!(!shown.contains("tenant-7"));
}
