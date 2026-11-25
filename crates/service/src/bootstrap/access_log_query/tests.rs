use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::get;
use iam_domain::AccessLogQueryError;
use iam_infrastructure::LokiQueryTransport as _;
use tokio::net::TcpListener;

use super::{HyperLokiQueryTransport, access_log_query};
use crate::config::{AccessLogQuerySettings, AppEnv};

type Seen = Arc<Mutex<Vec<(String, String)>>>;

#[derive(Clone)]
struct Stub {
    status: StatusCode,
    delay: Duration,
    seen: Seen,
}

async fn answer(State(stub): State<Stub>, headers: HeaderMap, uri: Uri) -> (StatusCode, String) {
    let tenant = headers
        .get("x-scope-orgid")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    stub.seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((tenant, uri.to_string()));
    tokio::time::sleep(stub.delay).await;
    (stub.status, "{\"status\":\"success\"}".to_owned())
}

#[expect(
    clippy::disallowed_methods,
    reason = "a unit test serves its stub of Loki on a free loopback port"
)]
async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Serves a Loki stub that answers `status` after `delay`; returns its base URL and what it saw.
async fn serve(status: StatusCode, delay: Duration) -> (String, Seen) {
    let seen = Seen::default();
    let listener = bind().await;
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/ready", get(answer))
        .route("/loki/api/v1/query_range", get(answer))
        .with_state(Stub {
            status,
            delay,
            seen: Arc::clone(&seen),
        });
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{address}"), seen)
}

const TIMEOUT: Duration = Duration::from_millis(400);

#[tokio::test]
async fn a_get_carries_the_tenant_and_returns_the_status_and_the_body() {
    let (base, seen) = serve(StatusCode::OK, Duration::ZERO).await;
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    let response = transport
        .get(&format!("{base}/loki/api/v1/query_range?query=x"))
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"status\":\"success\"}");
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        seen.as_slice(),
        [(
            "tenant-7".to_owned(),
            "/loki/api/v1/query_range?query=x".to_owned()
        )]
    );
}

#[tokio::test]
async fn an_error_status_is_returned_to_the_adapter_to_judge() {
    let (base, _seen) = serve(StatusCode::SERVICE_UNAVAILABLE, Duration::ZERO).await;
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    let response = transport.get(&format!("{base}/ready")).await.unwrap();

    assert_eq!(response.status, 503);
}

#[tokio::test]
async fn an_answer_slower_than_the_timeout_is_a_timeout() {
    let (base, _seen) = serve(StatusCode::OK, Duration::from_secs(5)).await;
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    let error = transport.get(&format!("{base}/ready")).await.unwrap_err();

    assert_eq!(error, AccessLogQueryError::Timeout);
}

#[tokio::test]
async fn a_refused_connection_is_unavailable() {
    let listener = bind().await;
    let address = listener.local_addr().unwrap();
    drop(listener);
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    let error = transport
        .get(&format!("http://{address}/ready"))
        .await
        .unwrap_err();

    assert_eq!(error, AccessLogQueryError::Unavailable);
}

#[tokio::test]
async fn a_url_that_is_not_a_uri_is_unavailable() {
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    let error = transport.get("not a url").await.unwrap_err();

    assert_eq!(error, AccessLogQueryError::Unavailable);
}

#[test]
fn a_tenant_that_cannot_be_a_header_value_is_refused() {
    assert!(HyperLokiQueryTransport::new("bad\ntenant", TIMEOUT).is_err());
}

#[test]
fn the_debug_form_does_not_show_the_tenant() {
    let transport = HyperLokiQueryTransport::new("tenant-7", TIMEOUT).unwrap();

    assert!(!format!("{transport:?}").contains("tenant-7"));
}

#[tokio::test]
async fn the_adapter_is_ready_when_the_ready_endpoint_answers() {
    let (base, seen) = serve(StatusCode::OK, Duration::ZERO).await;
    let settings = AccessLogQuerySettings {
        query_url: base.parse().unwrap(),
        tenant_id: "tenant-7".to_owned(),
        max_range: Duration::from_hours(24),
        timeout: TIMEOUT,
        cursor_key: None,
    };

    let store = access_log_query(&settings, AppEnv::Test).unwrap();

    assert_eq!(store.ready().await, Ok(()));
    assert_eq!(
        seen.lock().unwrap_or_else(PoisonError::into_inner)[0].1,
        "/ready"
    );
}
