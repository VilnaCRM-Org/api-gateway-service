//! The audit lane of the access log (Story 14.2, FR-50, NFR-24) in process: the production writer
//! thread pushing to a Loki, the audit gate, and a real [`Pipeline`] under audit-or-deny.
//!
//! One group of tests runs against a local HTTP stub of Loki that withholds its acknowledgements
//! on demand, with the time of the gate controlled; one test runs against the compose Loki, whose
//! push endpoint is `LOKI_PUSH_URL` of the test stack.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, Uri};
use axum::routing::post;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use iam_application::AuditGate;
use iam_domain::{AccessClass, AccessLane, ClassBudgets, SampleRate};
use iam_infrastructure::{
    LaneSplitSink, LokiPushAccessLogSink, LokiSinkSettings, StdoutAccessLogSink,
};
use serde_json::Value;
use service::bootstrap::gateway::access_log::loki_transport::HyperLokiTransport;
use service::bootstrap::gateway::access_log::{AccessLogAdapters, LOKI_APP_LABEL};
use service::config::{AccessLogSettings, AppEnv, AuditLaneSettings};
use shared_domain::Clock;
use shared_infrastructure::clock::SystemClock;
use test_support::clock::ManualClock;
use test_support::rng::FakeRng;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use crate::access_log::{GOOD, HOST, NOW, OTHER, at, pipeline_router, request};
use crate::support::stack_variable;

const MAX_PENDING: Duration = Duration::from_secs(5);

/// A Loki that answers a push 204 while it acknowledges and 503 while it withholds, and keeps what
/// it acknowledged.
#[derive(Debug, Clone, Default)]
struct LokiStub {
    acknowledging: Arc<AtomicBool>,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl LokiStub {
    fn acknowledge(&self) {
        self.acknowledging.store(true, Ordering::Release);
    }

    fn acknowledged_pushes(&self) -> usize {
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

async fn receive(State(stub): State<LokiStub>, body: String) -> StatusCode {
    if !stub.acknowledging.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    stub.bodies
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body);
    StatusCode::NO_CONTENT
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its stub of Loki on a free loopback port"
)]
async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Serves the stub; returns its push URL.
async fn serve(stub: &LokiStub) -> Uri {
    let listener = bind().await;
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/loki/api/v1/push", post(receive))
        .with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{address}/loki/api/v1/push")
        .parse()
        .unwrap()
}

/// A gateway on the production sinks, pushing to `push_url`: the writer, the audit gate over
/// `clock` and the pipeline under it.
struct Gateway {
    router: Router,
    access: AccessLogAdapters,
    clock: Arc<ManualClock>,
}

fn gateway(push_url: Uri, capacity: usize) -> Gateway {
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let shared: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
    let audit = AuditLaneSettings {
        push_url,
        tenant_id: "iam".to_owned(),
        flush_interval: Duration::from_millis(20),
        max_pending: MAX_PENDING,
    };
    let access = AccessLogAdapters::to_production(
        &AccessLogSettings {
            allow_sample_rate: SampleRate::NONE,
            class_budgets: ClassBudgets::default(),
            channel_capacity: capacity,
        },
        &audit,
        AppEnv::Test,
        Arc::new(FakeRng::seeded(7)),
        Arc::clone(&shared),
    )
    .unwrap();
    let router = pipeline_router(&shared, &access);
    Gateway {
        router,
        access,
        clock,
    }
}

/// The status and the problem `type` of the answer to `path` for `token`.
async fn answer(gateway: &Gateway, path: &str, token: &str) -> (StatusCode, Option<String>) {
    let response = gateway
        .router
        .clone()
        .oneshot(request(path, Some(token)))
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let kind = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|problem| problem["type"].as_str().map(str::to_owned));
    (status, kind)
}

/// Polls `condition` for up to ten seconds.
async fn eventually(condition: impl Fn() -> bool) -> bool {
    for _ in 0..1_000 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

const AUDIT_UNAVAILABLE: &str = "/problems/audit_unavailable";

#[tokio::test]
async fn audited_requests_are_refused_while_the_oldest_record_is_unacknowledged_for_too_long_and_served_again_after()
 {
    let stub = LokiStub::default();
    let gateway = gateway(serve(&stub).await, 64);
    let gate = gateway.access.audit_gate();
    assert_eq!(
        answer(&gateway, "/api/audit-me", GOOD).await,
        (StatusCode::OK, None)
    );
    assert!(eventually(|| gate.pending() == 1).await);

    gateway.clock.advance(Duration::from_secs(6));

    for path in ["/api/audit-me", "/api/secret"] {
        let (status, kind) = answer(&gateway, path, GOOD).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(kind.as_deref(), Some(AUDIT_UNAVAILABLE), "{path}");
    }
    assert_eq!(
        answer(&gateway, "/api/users/1", GOOD).await,
        (StatusCode::OK, None)
    );
    let (status, _kind) = answer(&gateway, "/api/users/1", OTHER).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let counters = gateway.access.counters();
    assert!(
        eventually(|| counters.dropped_count(AccessLane::Audit, AccessClass::Audit) >= 1).await
    );

    stub.acknowledge();

    assert!(eventually(|| gate.pending() == 0).await);
    assert_eq!(
        answer(&gateway, "/api/audit-me", GOOD).await,
        (StatusCode::OK, None)
    );
    assert!(stub.acknowledged_pushes() >= 1);
    gateway.access.finish();
}

#[tokio::test]
async fn a_full_audit_lane_refuses_an_audited_request_with_503() {
    let stub = LokiStub::default();
    let gateway = gateway(serve(&stub).await, 2);
    let gate = gateway.access.audit_gate();
    for _ in 0..2 {
        assert_eq!(
            answer(&gateway, "/api/audit-me", GOOD).await,
            (StatusCode::OK, None)
        );
    }
    assert!(eventually(|| gate.pending() == 2).await);

    let (status, kind) = answer(&gateway, "/api/audit-me", GOOD).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(kind.as_deref(), Some(AUDIT_UNAVAILABLE));
    assert_eq!(
        answer(&gateway, "/api/users/1", GOOD).await,
        (StatusCode::OK, None)
    );
    gateway.access.finish();
}

#[tokio::test]
async fn a_loki_that_acknowledges_keeps_the_lane_open_and_receives_each_record_once() {
    let stub = LokiStub::default();
    stub.acknowledge();
    let gateway = gateway(serve(&stub).await, 64);
    let gate = gateway.access.audit_gate();

    for _ in 0..5 {
        assert_eq!(
            answer(&gateway, "/api/audit-me", GOOD).await,
            (StatusCode::OK, None)
        );
    }
    assert!(eventually(|| gate.pending() == 0 && stub.acknowledged_pushes() >= 1).await);
    gateway.access.finish();

    let mut ids: Vec<String> = {
        let bodies = stub.bodies.lock().unwrap_or_else(PoisonError::into_inner);
        bodies
            .iter()
            .flat_map(|body| {
                let body: Value = serde_json::from_str(body).unwrap();
                body["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|stream| stream["values"].as_array().unwrap().clone())
                    .map(|value| value[2]["decision_id"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    assert_eq!(ids.len(), 5);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 5);
}

/// A writer that several owners share, standing in for stdout.
#[derive(Debug, Clone, Default)]
struct SharedStdout(Arc<Mutex<Vec<u8>>>);

impl Write for SharedStdout {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedStdout {
    fn text(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap()
    }
}

/// The text of `value` as the label or metadata `name`, from the metadata of the value when Loki
/// categorises it and from the labels of the stream otherwise.
fn field(stream: &Value, value: &Value, name: &str) -> Option<String> {
    value[2]["structuredMetadata"][name]
        .as_str()
        .or_else(|| stream["stream"][name].as_str())
        .map(str::to_owned)
}

fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// `GET <path_and_query>` on the Loki that `push_url` names, as the tenant `iam`.
async fn loki_get(push_url: &Uri, path_and_query: &str) -> Value {
    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let uri = format!("http://{}{path_and_query}", push_url.authority().unwrap());
    let request = Request::get(uri)
        .header("X-Scope-OrgID", "iam")
        .header("X-Loki-Response-Encoding-Flags", "categorize-labels")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = client.request(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

/// The streams of the audit lane whose `request_id` is `request_id`, from `start_ns` on.
async fn audit_streams(push_url: &Uri, request_id: &str, start_ns: u128) -> Vec<Value> {
    let query = format!(
        "{{app=\"{LOKI_APP_LABEL}\",env=\"test\",lane=\"audit\"}} | request_id=\"{request_id}\""
    );
    let path = format!(
        "/loki/api/v1/query_range?query={}&start={start_ns}&limit=100&direction=forward",
        encoded(&query)
    );
    let body = loki_get(push_url, &path).await;
    body["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn request_with_id(path: &str, token: &str, id: &str) -> Request<Body> {
    Request::get(path)
        .header("host", HOST)
        .header("authorization", format!("Bearer {token}"))
        .header("x-request-id", id)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_compose_loki_returns_each_audit_record_once_with_its_labels_and_none_reaches_stdout() {
    let push_url: Uri = stack_variable("LOKI_PUSH_URL").parse().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let started_ns = clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique = format!("audit-it-{started_ns}");
    let stdout = SharedStdout::default();
    let loki = LokiPushAccessLogSink::start(
        LokiSinkSettings {
            app: LOKI_APP_LABEL.to_owned(),
            env: "test".to_owned(),
            flush_interval: Duration::from_millis(100),
        },
        Arc::new(HyperLokiTransport::new(push_url.clone(), "iam").unwrap()),
    )
    .unwrap();
    let sink = LaneSplitSink::new(
        Arc::new(StdoutAccessLogSink::to_writer(stdout.clone())),
        Arc::new(loki),
    );
    let gate = Arc::new(AuditGate::new(Arc::clone(&clock), MAX_PENDING, 1_024));
    let access = AccessLogAdapters::start_gated(
        &AccessLogSettings {
            allow_sample_rate: SampleRate::ALL,
            class_budgets: ClassBudgets::default(),
            channel_capacity: 1_024,
        },
        gate,
        Arc::new(FakeRng::seeded(11)),
        Arc::clone(&clock),
        Arc::new(sink),
    )
    .unwrap();
    let router = pipeline_router(&clock, &access);
    let allowed = format!("{unique}-allowed");
    let denied = format!("{unique}-denied");

    let first = router
        .clone()
        .oneshot(request_with_id("/api/audit-me", GOOD, &allowed))
        .await
        .unwrap();
    let second = router
        .clone()
        .oneshot(request_with_id("/api/users/1", OTHER, &denied))
        .await
        .unwrap();
    router
        .clone()
        .oneshot(request_with_id(
            "/api/users/1",
            GOOD,
            &format!("{unique}-ordinary"),
        ))
        .await
        .unwrap();
    access.finish();

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    for (id, decision) in [(&allowed, "allow"), (&denied, "deny")] {
        let mut found = Vec::new();
        for _ in 0..200 {
            found = audit_streams(&push_url, id, started_ns).await;
            if !found.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let values: Vec<(&Value, &Value)> = found
            .iter()
            .flat_map(|stream| {
                stream["values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(move |value| (stream, value))
            })
            .collect();
        assert_eq!(values.len(), 1, "{id}: {found:?}");
        let (stream, value) = values[0];
        assert_eq!(stream["stream"]["app"], LOKI_APP_LABEL);
        assert_eq!(stream["stream"]["env"], "test");
        assert_eq!(stream["stream"]["lane"], "audit");
        assert_eq!(stream["stream"]["decision"], decision);
        assert_eq!(stream["stream"]["upstream"], "backend");
        for name in [
            "decision_id",
            "request_id",
            "route_id",
            "status",
            "reason",
            "policy_version",
            "subject_kind",
            "subject_id",
        ] {
            assert!(field(stream, value, name).is_some(), "{id}: {name}");
        }
        assert_eq!(
            field(stream, value, "request_id").as_deref(),
            Some(id.as_str())
        );
    }
    let written = stdout.text();
    assert!(!written.contains("\"lane\":\"audit\""), "{written}");
    assert!(written.contains(&format!("{unique}-ordinary")));
}
