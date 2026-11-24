//! A fake Kubernetes API server for `EndpointSlices`: it answers `list` and `watch` over plain HTTP
//! and records every request it receives.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Sleep;

/// How long a watch waits for an event before the server ends the stream.
const WATCH_WAIT: Duration = Duration::from_millis(300);

/// How long a broken body waits after its chunks before it fails, so that the status line and
/// the chunks reach the client first.
const BREAK_DELAY: Duration = Duration::from_millis(50);

/// One endpoint of a slice.
#[derive(Debug, Clone)]
pub(super) struct FakeEndpoint {
    address: String,
    zone: String,
    ready: bool,
    terminating: bool,
}

impl FakeEndpoint {
    pub(super) fn ready(address: &str, zone: &str) -> Self {
        Self {
            ready: true,
            ..Self::with(address, zone)
        }
    }

    pub(super) fn not_ready(address: &str, zone: &str) -> Self {
        Self::with(address, zone)
    }

    pub(super) fn terminating(address: &str, zone: &str) -> Self {
        Self {
            terminating: true,
            ..Self::with(address, zone)
        }
    }

    fn with(address: &str, zone: &str) -> Self {
        Self {
            address: address.to_owned(),
            zone: zone.to_owned(),
            ready: false,
            terminating: false,
        }
    }

    fn json(&self) -> Value {
        json!({
            "addresses": [self.address],
            "conditions": {
                "ready": self.ready,
                "serving": self.ready || self.terminating,
                "terminating": self.terminating
            },
            "zone": self.zone,
            "targetRef": {"kind": "Pod", "name": format!("pod-{}", self.address)}
        })
    }
}

/// A request the server received.
#[derive(Debug, Clone)]
pub(super) struct Recorded {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) query: String,
    pub(super) authorization: Option<String>,
}

#[derive(Debug, Default)]
struct State {
    version: u64,
    slices: BTreeMap<String, Value>,
    events: Vec<(u64, &'static str, Value)>,
    compacted_before: u64,
    drop_next_watch: bool,
    gone_in_stream: bool,
    fail_with: Option<u16>,
    next_answer: Option<Answer>,
    requests: Vec<Recorded>,
}

/// An answer that the test sets for the next request.
#[derive(Debug)]
struct Answer {
    status: u16,
    chunks: Vec<String>,
    broken: bool,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    changed: Notify,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The running fake; the server stops when it is dropped.
#[derive(Debug)]
pub(super) struct FakeKubernetesApi {
    address: SocketAddr,
    shared: Arc<Shared>,
    server: JoinHandle<()>,
}

impl Drop for FakeKubernetesApi {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl FakeKubernetesApi {
    #[expect(
        clippy::disallowed_methods,
        reason = "an integration test serves the fake API on a free loopback port"
    )]
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::new(Shared::default());
        let server = tokio::spawn(serve(listener, Arc::clone(&shared)));
        Self {
            address,
            shared,
            server,
        }
    }

    pub(super) fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The current resource version.
    pub(super) fn version(&self) -> u64 {
        self.shared.state().version
    }

    /// Adds the slice, or replaces its endpoints, as one event.
    pub(super) fn put_slice(&self, name: &str, endpoints: &[FakeEndpoint]) {
        let mut state = self.shared.state();
        state.version = state.version.saturating_add(1);
        let kind = if state.slices.contains_key(name) {
            "MODIFIED"
        } else {
            "ADDED"
        };
        let object = slice_json(name, state.version, endpoints);
        state.slices.insert(name.to_owned(), object.clone());
        let version = state.version;
        state.events.push((version, kind, object));
        drop(state);
        self.shared.changed.notify_waiters();
    }

    /// Deletes the slice as one event.
    pub(super) fn delete_slice(&self, name: &str) {
        let mut state = self.shared.state();
        state.version = state.version.saturating_add(1);
        let version = state.version;
        let object = slice_json(name, version, &[]);
        state.slices.remove(name);
        state.events.push((version, "DELETED", object));
        drop(state);
        self.shared.changed.notify_waiters();
    }

    /// Forgets the events so far: a watch from an older version gets a 410.
    pub(super) fn compact(&self) {
        let mut state = self.shared.state();
        state.compacted_before = state.version;
        state.events.clear();
    }

    /// The next watch request loses its connection before the response.
    pub(super) fn drop_next_watch(&self) {
        self.shared.state().drop_next_watch = true;
    }

    /// The next watch answers 200 with an `ERROR` event of code 410.
    pub(super) fn gone_in_stream(&self) {
        self.shared.state().gone_in_stream = true;
    }

    /// Every request answers this status.
    pub(super) fn fail_with(&self, status: u16) {
        self.shared.state().fail_with = Some(status);
    }

    /// The next request, a list or a watch, answers `status` with a body of `chunks`, one frame
    /// each; when `broken`, the body then fails instead of ending.
    pub(super) fn answer_next(&self, status: u16, chunks: &[&str], broken: bool) {
        self.shared.state().next_answer = Some(Answer {
            status,
            chunks: chunks.iter().map(|chunk| (*chunk).to_owned()).collect(),
            broken,
        });
    }

    /// The requests received so far, oldest first.
    pub(super) fn requests(&self) -> Vec<Recorded> {
        self.shared.state().requests.clone()
    }
}

fn slice_json(name: &str, version: u64, endpoints: &[FakeEndpoint]) -> Value {
    json!({
        "metadata": {
            "name": name,
            "resourceVersion": version.to_string(),
            "labels": {"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}
        },
        "addressType": "IPv4",
        "endpoints": endpoints.iter().map(FakeEndpoint::json).collect::<Vec<_>>(),
        "ports": [{"name": "http", "port": 8081, "protocol": "TCP"}]
    })
}

async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((stream, _peer)) = listener.accept().await {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let service = service_fn(move |request| handle(Arc::clone(&shared), request));
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap_or_default();
        });
    }
}

/// A body of ready chunks that ends, or fails a moment after its chunks when it is broken.
#[derive(Debug)]
struct Chunks {
    pending: VecDeque<Bytes>,
    broken: bool,
    delay: Option<Pin<Box<Sleep>>>,
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = Dropped;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Dropped>>> {
        let this = self.get_mut();
        if let Some(chunk) = this.pending.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if !this.broken {
            return Poll::Ready(None);
        }
        let delay = this
            .delay
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(BREAK_DELAY)));
        if delay.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        this.broken = false;
        Poll::Ready(Some(Err(Dropped)))
    }
}

fn reply(status: StatusCode, chunks: Vec<String>) -> Response<Chunks> {
    answer(Answer {
        status: status.as_u16(),
        chunks,
        broken: false,
    })
}

fn answer(answer: Answer) -> Response<Chunks> {
    let mut response = Response::new(Chunks {
        pending: answer.chunks.into_iter().map(Bytes::from).collect(),
        broken: answer.broken,
        delay: None,
    });
    *response.status_mut() = StatusCode::from_u16(answer.status).unwrap();
    response
}

/// The connection is dropped without an answer: the service fails, hyper closes the socket.
#[derive(Debug, thiserror::Error)]
#[error("the fake API dropped the connection")]
struct Dropped;

async fn handle(
    shared: Arc<Shared>,
    request: Request<Incoming>,
) -> Result<Response<Chunks>, Dropped> {
    let query = request.uri().query().unwrap_or_default().to_owned();
    let watching = query.contains("watch=true");
    let (status, next) = {
        let mut state = shared.state();
        state.requests.push(Recorded {
            method: request.method().to_string(),
            path: request.uri().path().to_owned(),
            query: query.clone(),
            authorization: request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
        (state.fail_with, state.next_answer.take())
    };
    if let Some(next) = next {
        return Ok(answer(next));
    }
    if let Some(code) = status {
        return Ok(reply(
            StatusCode::from_u16(code).unwrap(),
            vec![String::new()],
        ));
    }
    if !watching {
        return Ok(list(&shared));
    }
    if std::mem::take(&mut shared.state().drop_next_watch) {
        return Err(Dropped);
    }
    Ok(watch(&shared, &query).await)
}

fn list(shared: &Shared) -> Response<Chunks> {
    let body = {
        let state = shared.state();
        json!({
            "kind": "EndpointSliceList",
            "metadata": {"resourceVersion": state.version.to_string()},
            "items": state.slices.values().collect::<Vec<_>>()
        })
    };
    reply(StatusCode::OK, vec![body.to_string()])
}

fn requested_version(query: &str) -> u64 {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("resourceVersion="))
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

async fn watch(shared: &Shared, query: &str) -> Response<Chunks> {
    let resume = requested_version(query);
    let waiting = shared.changed.notified();
    {
        let mut state = shared.state();
        if resume < state.compacted_before {
            let status = json!({"kind": "Status", "code": 410, "reason": "Expired"});
            return reply(StatusCode::GONE, vec![status.to_string()]);
        }
        if std::mem::take(&mut state.gone_in_stream) {
            let status = json!({"kind": "Status", "code": 410, "reason": "Expired"});
            let line = json!({"type": "ERROR", "object": status});
            return reply(StatusCode::OK, vec![format!("{line}\n")]);
        }
    }
    if events_after(shared, resume).is_empty() {
        tokio::time::timeout(WATCH_WAIT, waiting)
            .await
            .unwrap_or_default();
    }
    let lines = events_after(shared, resume)
        .into_iter()
        .map(|(kind, object)| format!("{}\n", json!({"type": kind, "object": object})))
        .collect();
    reply(StatusCode::OK, lines)
}

fn events_after(shared: &Shared, resume: u64) -> Vec<(&'static str, Value)> {
    shared
        .state()
        .events
        .iter()
        .filter(|(version, _kind, _object)| *version > resume)
        .map(|(_version, kind, object)| (*kind, object.clone()))
        .collect()
}
