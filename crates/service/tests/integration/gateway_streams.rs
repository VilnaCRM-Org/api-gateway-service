//! WebSocket and SSE streams through the gateway (Story 11.1): the production pipeline, the stream
//! registry and the `HyperUpstreamForwarder` in front of a fake upstream with a WebSocket echo and
//! an SSE endpoint, served on loopback sockets. Tokens, assignments and the freshness proof run on
//! controlled clocks that a test moves forward.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::routing::get;
use hyper::body::{Frame, SizeHint};
use hyper_util::rt::TokioIo;
use iam_application::{
    EndpointDirectory, FreshnessState, Principal, ReevaluationBoard, RequestAuthorizer,
    StreamReauthorizer, ZoneSource,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CatalogueEntryState, CompiledRoleSet, EndpointConditions,
    EndpointParts, EndpointSlice, FreshnessRule, GlobalRevocationState, GrantStatus, HttpMethod,
    PermissionGrant, PolicyChange, PolicySnapshot, PolicyTouch, PolicyVersion, PolicyView,
    RevocationView, RoleId, RouteFlag, RouteFlags, RouteState, ServiceName, SessionId, StateKey,
    SubjectId, SubjectRef, TokenId, TokenIdentity, TokenMemo, TokenRepository, UpstreamEndpoint,
    UpstreamState, UserRevocationState, WatchTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings,
};
use service::bootstrap::gateway::pipeline::{Forwarder, Pipeline, UnauditedCommands, router};
use service::bootstrap::gateway::streams::{
    CloseReason, Grant, PodFence, StreamHandle, StreamRecord, StreamSettings, Streams, close_frame,
};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::ManualClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::rng::FakeRng;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

const HOST: &str = "api.example.test";
const NOW: u64 = 1_800_000_000;
const HARD_BOUND: Duration = Duration::from_secs(15);
const BOUND: Duration = Duration::from_secs(10);
const WS_KEY: &str = "rest:streams:GET /ws";
const EVENTS_KEY: &str = "rest:streams:GET /events";

/// A subject of the scenarios: how long its token lives and the assignments that grant it the keys
/// (`None` never expires).
struct Subject {
    name: &'static str,
    token_seconds: u64,
    assignments: &'static [Option<u64>],
}

const ALICE: Subject = Subject {
    name: "alice",
    token_seconds: 900,
    assignments: &[Some(600)],
};
const BOB: Subject = Subject {
    name: "bob",
    token_seconds: 900,
    assignments: &[Some(600), None],
};
const CAROL: Subject = Subject {
    name: "carol",
    token_seconds: 900,
    assignments: &[],
};
const DAVE: Subject = Subject {
    name: "dave",
    token_seconds: 300,
    assignments: &[None],
};
const SUBJECTS: [&Subject; 4] = [&ALICE, &BOB, &CAROL, &DAVE];

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user_id(index: usize) -> Uuid {
    Uuid::parse(&format!(
        "3d9b7c1e-5a2f-4e8d-b6c0-{:012x}",
        index.saturating_add(1)
    ))
    .unwrap()
}

fn role_id(subject: usize, assignment: usize) -> RoleId {
    RoleId::parse(&format!(
        "0190f2a8-7b3c-7d4e-8f10-{:06x}{:06x}",
        subject.saturating_add(1),
        assignment.saturating_add(1)
    ))
    .unwrap()
}

fn subject_text(name: &str) -> String {
    let index = SUBJECTS
        .iter()
        .position(|subject| subject.name == name)
        .unwrap();
    user_id(index).to_string()
}

fn token_of(index: usize, subject: &Subject) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(user_id(index)),
        session: Some(SessionId::new(&format!("session-{}", subject.name)).unwrap()),
        token_id: TokenId::new(&format!("token-{}", subject.name)).unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW.saturating_sub(60)),
        expires_at: at(NOW.saturating_add(subject.token_seconds)),
    })
}

fn micros(seconds: u64) -> Option<i64> {
    i64::try_from(seconds.saturating_mul(1_000_000)).ok()
}

/// What the fake upstream saw.
#[derive(Debug, Clone, Default)]
struct Seen(Arc<AtomicUsize>);

/// An event stream that stays open while its receiver does.
struct Events(mpsc::Receiver<Bytes>);

impl hyper::body::Body for Events {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(context)
            .map(|bytes| bytes.map(|bytes| Ok(Frame::data(bytes))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// The WebSocket endpoint of the fake upstream: it answers `101` and echoes every byte.
async fn websocket(State(seen): State<Seen>, request: Request) -> Response {
    seen.0.fetch_add(1, Ordering::SeqCst);
    let upgraded = hyper::upgrade::on(request);
    drop(tokio::spawn(async move {
        if let Ok(upgraded) = upgraded.await {
            let (mut reader, mut writer) = tokio::io::split(TokioIo::new(upgraded));
            drop(tokio::io::copy(&mut reader, &mut writer).await);
        }
    }));
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        .body(Body::empty())
        .unwrap()
}

/// The SSE endpoint of the fake upstream: one event, then the stream stays open.
async fn events(State(seen): State<Seen>) -> Response {
    seen.0.fetch_add(1, Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel(8);
    sender
        .send(Bytes::from_static(b"data: hello\n\n"))
        .await
        .unwrap();
    drop(tokio::spawn(async move { sender.closed().await }));
    Response::builder()
        .header(CONTENT_TYPE, "text/event-stream")
        .body(Body::new(Events(receiver)))
        .unwrap()
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

async fn serve(router: Router) -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    address
}

fn snapshot() -> GatewaySnapshot {
    snapshot_at(7, &SUBJECTS)
}

/// The snapshot at `version` in which only `holders` hold their keys.
fn snapshot_at(version: i64, holders: &[&Subject]) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let streams = UpstreamState::of(upstream(&mut rng, "streams", "streams").parts());
    let flags = RouteFlags::default().with(RouteFlag::Streaming, true);
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(version).unwrap())
        .with_upstream(streams.clone())
        .with_catalogue(
            ServiceName::new("streams").unwrap(),
            [WS_KEY, EVENTS_KEY]
                .map(|key| CatalogueEntryState::untyped(key.to_owned(), [false, false]))
                .to_vec(),
        );
    for path in ["/ws", "/events"] {
        let mut draft = route_draft(HOST, path, &[HttpMethod::Get], "streams", streams.id);
        draft.flags = flags;
        snapshot = snapshot.with_route(RouteState::of(route(&mut rng, &draft).parts()));
    }
    for (index, subject) in SUBJECTS.iter().enumerate() {
        if holders.iter().any(|holder| holder.name == subject.name) {
            snapshot = with_subject(snapshot, index, subject);
        }
    }
    snapshot
}

/// A policy view whose snapshot a test replaces, as the apply thread publishes a version.
#[derive(Debug)]
struct Moving(Mutex<Arc<dyn PolicySnapshot>>);

impl Moving {
    fn serving(snapshot: GatewaySnapshot) -> Self {
        Self(Mutex::new(Arc::new(snapshot)))
    }

    fn publish(&self, snapshot: GatewaySnapshot) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(snapshot);
    }
}

impl PolicyView for Moving {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        Some(Arc::clone(
            &self.0.lock().unwrap_or_else(PoisonError::into_inner),
        ))
    }
}

fn with_subject(snapshot: GatewaySnapshot, index: usize, subject: &Subject) -> GatewaySnapshot {
    let grants =
        [WS_KEY, EVENTS_KEY].map(|key| (PermissionGrant::parse(key).unwrap(), GrantStatus::Active));
    let mut snapshot = snapshot;
    let mut held = Vec::new();
    for (number, expires) in subject.assignments.iter().enumerate() {
        let role = role_id(index, number);
        held.push(AssignmentState {
            role,
            scope: AssignmentScope::Global,
            expires_at_micros: expires.and_then(|seconds| micros(NOW.saturating_add(seconds))),
        });
        snapshot = snapshot.with_role_set(role, CompiledRoleSet::compile(grants.clone()));
    }
    snapshot.with_assignments(SubjectRef::user(user_id(index)), held)
}

fn directory_of(address: SocketAddr) -> EndpointDirectory {
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
            service: "streams-service".to_owned(),
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
    directory
}

/// The gateway of a scenario and what a test moves.
struct Harness {
    address: SocketAddr,
    upstream_requests: Seen,
    streams: Arc<Streams>,
    clock: Arc<ManualClock>,
    boot: Arc<FakeBootClock>,
    freshness: Arc<FreshnessState>,
    moving: Arc<Moving>,
    board: Arc<ReevaluationBoard>,
    _stop: watch::Sender<bool>,
}

impl Harness {
    async fn start(per_subject: usize) -> Self {
        let seen = Seen::default();
        let fake = Router::new()
            .route("/ws", get(websocket))
            .route("/events", get(events))
            .with_state(seen.clone());
        let upstream_address = serve(fake).await;
        let forwarder: Arc<Forwarder> = Arc::new(HyperUpstreamForwarder::new(
            directory_of(upstream_address).view(),
            true,
            Arc::new(FakeRng::seeded(1)),
        ));
        let boot = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
            Duration::from_secs(100),
        )));
        let freshness = Arc::new(FreshnessState::new(
            FreshnessRule::new(HARD_BOUND, Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&boot),
        ));
        freshness.attach(
            FreshnessProof {
                taken_at: boot.now(),
                watermark: 1,
            },
            PolicyVersion::new(7).unwrap(),
        );
        let clock = Arc::new(ManualClock::at(at(NOW)));
        let moving = Arc::new(Moving::serving(snapshot()));
        let view: Arc<dyn PolicyView> = Arc::<Moving>::clone(&moving);
        let streams = Streams::new(
            StreamSettings {
                idle_timeout: Duration::from_mins(5),
                per_subject,
            },
            Arc::<ManualClock>::clone(&clock),
        );
        let policy_clock: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
        let pipeline = pipeline_over(&view, &freshness, &policy_clock, forwarder)
            .with_streams(Arc::clone(&streams));
        let (stop, stopping) = watch::channel(false);
        let board = Arc::new(ReevaluationBoard::new());
        let reauthorizer = Arc::new(StreamReauthorizer::new(
            Arc::<Streams>::clone(&streams),
            Arc::clone(&view),
            Arc::clone(&board),
        ));
        drop(tokio::spawn(reauthorizer.run(stopping.clone())));
        let fence = Arc::new(PodFence::new(view, Arc::clone(&freshness)));
        drop(tokio::spawn(Arc::clone(&streams).watch(fence, stopping)));
        Self {
            address: serve(router(pipeline)).await,
            upstream_requests: seen,
            streams,
            clock,
            boot,
            freshness,
            moving,
            board,
            _stop: stop,
        }
    }

    /// Publishes `snapshot` and hands the apply thread's report of it, with what it touched, to
    /// the re-authorization; completes once that has decided the streams of the version.
    async fn apply(&self, snapshot: GatewaySnapshot, touched: &[String]) {
        let version = snapshot.version();
        self.moving.publish(snapshot);
        let mut touch = PolicyTouch::nothing();
        for key in touched {
            touch.note(&StateKey::parse(key).unwrap());
        }
        self.board.submit(PolicyChange { version, touch });
        tokio::time::timeout(BOUND, self.board.reached(version))
            .await
            .unwrap();
    }

    fn upstream_saw(&self) -> usize {
        self.upstream_requests.0.load(Ordering::SeqCst)
    }

    async fn websocket(&self, subject: Option<&str>) -> (TcpStream, String) {
        self.open("/ws", subject, true).await
    }

    async fn events(&self, subject: Option<&str>) -> (TcpStream, String) {
        self.open("/events", subject, false).await
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "an integration test connects to the gateway it started on loopback"
    )]
    async fn open(&self, path: &str, subject: Option<&str>, upgrade: bool) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream
            .write_all(request_text(path, subject, upgrade).as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut stream).await;
        (stream, head)
    }
}

fn pipeline_over(
    view: &Arc<dyn PolicyView>,
    freshness: &Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
    forwarder: Arc<Forwarder>,
) -> Pipeline {
    let verifier = SUBJECTS.iter().enumerate().fold(
        FakeAccessTokenVerifier::new(),
        |verifier, (index, subject)| {
            verifier.accepting(
                &format!("{}.token.value", subject.name),
                token_of(index, subject),
            )
        },
    );
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(verifier);
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(5),
        },
        Arc::clone(clock),
    ));
    let revocations: Arc<dyn RevocationView> =
        Arc::new(SnapshotRevocationView::new(Arc::clone(view)));
    let tokens = Arc::new(CachingTokenRepository::new(verifier, memo, revocations));
    let token_port: Arc<dyn TokenRepository> = Arc::<CachingTokenRepository>::clone(&tokens);
    let commands: Arc<dyn CommandBus> = Arc::new(UnauditedCommands);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    Pipeline::new(
        Arc::clone(view),
        Arc::clone(freshness),
        tokens,
        Arc::new(authorizer),
        forwarder,
    )
}

fn request_text(path: &str, subject: Option<&str>, upgrade: bool) -> String {
    let mut text = format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n");
    if upgrade {
        text.push_str(
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        );
    } else {
        text.push_str("Accept: text/event-stream\r\nConnection: close\r\n");
    }
    if let Some(subject) = subject {
        text.push_str(&["Authorization: Bearer ", subject, ".token.value\r\n"].concat());
    }
    text.push_str("\r\n");
    text
}

/// The status line and the headers of an answer, read up to the empty line.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    tokio::time::timeout(BOUND, async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    String::from_utf8(head).unwrap()
}

fn status_of(head: &str) -> u16 {
    head.split(' ').nth(1).unwrap().parse().unwrap()
}

/// Reads until the bytes read hold `needle`.
async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    tokio::time::timeout(BOUND, async {
        let mut chunk = [0_u8; 256];
        while !seen.windows(needle.len()).any(|window| window == needle) {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "the stream ended before {needle:?}");
            seen.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .unwrap();
    seen
}

async fn read_exactly(stream: &mut TcpStream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    tokio::time::timeout(BOUND, stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

/// Reads to the end of the stream, which an SSE stream that the gateway ended reaches after its
/// last chunk.
async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut rest = Vec::new();
    tokio::time::timeout(BOUND, stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    rest
}

async fn echo(stream: &mut TcpStream, frame: &[u8]) {
    stream.write_all(frame).await.unwrap();
    assert_eq!(read_exactly(stream, frame.len()).await, frame);
}

async fn the_stream_ended_with_the_frame(stream: &mut TcpStream, code: u16) {
    let rest = read_to_end(stream).await;
    assert_eq!(rest, close_frame(code));
}

async fn the_event_stream_ended(stream: &mut TcpStream) {
    let rest = read_to_end(stream).await;
    assert!(
        rest.ends_with(b"0\r\n\r\n"),
        "the chunked body ended: {rest:?}"
    );
}

#[tokio::test]
async fn frames_and_events_flow_and_the_registry_holds_both_streams_of_the_subject() {
    let harness = Harness::start(8).await;

    let (mut socket, head) = harness.websocket(Some("alice")).await;
    let (mut events, events_head) = harness.events(Some("alice")).await;

    assert_eq!(status_of(&head), 101);
    assert!(head.to_ascii_lowercase().contains("upgrade: websocket"));
    echo(&mut socket, b"\x81\x05hello").await;
    echo(&mut socket, b"\x81\x07again!!").await;
    assert_eq!(status_of(&events_head), 200);
    assert!(
        events_head
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream")
    );
    read_until(&mut events, b"data: hello\n\n").await;
    let registry = harness.streams.registry();
    assert_eq!(registry.len(), 2);
    assert_eq!(registry.held_by_subject(&subject_text("alice")), 2);
    assert_eq!(registry.held_by_session("session-alice"), 2);
    assert_eq!(harness.upstream_saw(), 2);
}

#[tokio::test]
async fn a_subject_without_the_key_and_a_request_without_a_token_never_reach_the_upstream() {
    let harness = Harness::start(8).await;

    let (_denied, denied) = harness.websocket(Some("carol")).await;
    let (_anonymous, anonymous) = harness.websocket(None).await;
    let (_denied_events, denied_events) = harness.events(Some("carol")).await;

    assert_eq!(status_of(&denied), 403);
    assert_eq!(status_of(&anonymous), 401);
    assert_eq!(status_of(&denied_events), 403);
    assert_eq!(harness.upstream_saw(), 0);
    assert!(harness.streams.registry().is_empty());
}

#[tokio::test]
async fn a_stream_is_closed_and_removed_when_its_token_expires_on_the_controlled_clock() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("dave")).await;
    let (mut events, _events_head) = harness.events(Some("dave")).await;
    echo(&mut socket, b"\x81\x02hi").await;
    read_until(&mut events, b"data: hello\n\n").await;
    assert_eq!(harness.streams.registry().len(), 2);

    harness.clock.advance(Duration::from_mins(5));

    the_stream_ended_with_the_frame(&mut socket, 1008).await;
    the_event_stream_ended(&mut events).await;
    assert!(harness.streams.registry().is_empty());
}

#[tokio::test]
async fn streams_authorized_only_by_an_expiring_assignment_close_with_it_and_others_stay() {
    let harness = Harness::start(8).await;
    let (mut alice_socket, _head) = harness.websocket(Some("alice")).await;
    let (mut alice_events, _events_head) = harness.events(Some("alice")).await;
    let (mut bob_socket, _bob_head) = harness.websocket(Some("bob")).await;
    let (mut bob_events, _bob_events_head) = harness.events(Some("bob")).await;
    read_until(&mut alice_events, b"data: hello\n\n").await;
    read_until(&mut bob_events, b"data: hello\n\n").await;
    harness.clock.advance(Duration::from_secs(599));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(harness.streams.registry().len(), 4);

    harness.clock.advance(Duration::from_secs(1));

    the_stream_ended_with_the_frame(&mut alice_socket, 1008).await;
    the_event_stream_ended(&mut alice_events).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(harness.streams.registry().len(), 2);
    assert_eq!(
        harness
            .streams
            .registry()
            .held_by_subject(&subject_text("bob")),
        2
    );
    echo(&mut bob_socket, b"\x81\x04bob!").await;
}

#[tokio::test]
async fn a_pod_whose_proof_is_older_than_the_hard_bound_closes_every_stream() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    let (mut events, _events_head) = harness.events(Some("bob")).await;
    read_until(&mut events, b"data: hello\n\n").await;
    assert_eq!(harness.streams.registry().len(), 2);

    harness
        .boot
        .advance(HARD_BOUND.saturating_add(Duration::from_secs(1)));

    the_stream_ended_with_the_frame(&mut socket, 1013).await;
    the_event_stream_ended(&mut events).await;
    assert!(harness.streams.registry().is_empty());
}

#[tokio::test]
async fn a_pod_that_fences_closes_its_websockets_with_1013_and_ends_its_event_streams() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    let (mut events, _events_head) = harness.events(Some("alice")).await;
    read_until(&mut events, b"data: hello\n\n").await;

    harness.freshness.invalidate();

    the_stream_ended_with_the_frame(&mut socket, 1013).await;
    the_event_stream_ended(&mut events).await;
    assert!(harness.streams.registry().is_empty());
}

#[tokio::test]
async fn a_subject_at_its_stream_cap_is_refused_with_429_and_a_closed_stream_frees_a_slot() {
    let harness = Harness::start(1).await;
    let (first_socket, first_head) = harness.websocket(Some("alice")).await;
    assert_eq!(status_of(&first_head), 101);

    let (_over_cap, over_cap) = harness.events(Some("alice")).await;
    let (_another, another) = harness.events(Some("bob")).await;

    assert_eq!(status_of(&over_cap), 429);
    assert!(over_cap.contains("retry-after: 1"));
    assert_eq!(status_of(&another), 200);
    assert_eq!(harness.upstream_saw(), 2);
    drop(first_socket);
    tokio::time::timeout(BOUND, async {
        while harness
            .streams
            .registry()
            .held_by_subject(&subject_text("alice"))
            > 0
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let (_again, again) = harness.events(Some("alice")).await;
    assert_eq!(status_of(&again), 200);
}

fn subject_key(index: usize) -> String {
    format!("subject/user/{}", user_id(index))
}

#[tokio::test]
async fn a_stream_of_a_subject_whose_role_is_revoked_closes_before_the_version_is_finished() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    let (mut events, _events_head) = harness.events(Some("alice")).await;
    let (mut bob_socket, _bob_head) = harness.websocket(Some("bob")).await;
    read_until(&mut events, b"data: hello\n\n").await;
    let revoked = snapshot_at(8, &[&BOB, &CAROL, &DAVE]);

    harness.apply(revoked, &[subject_key(0)]).await;

    assert_eq!(harness.board.finished(), 8);
    assert_eq!(
        harness
            .streams
            .registry()
            .held_by_subject(&subject_text("alice")),
        0,
        "the streams were closed before the record reached the version"
    );
    the_stream_ended_with_the_frame(&mut socket, 1008).await;
    the_event_stream_ended(&mut events).await;
    echo(&mut bob_socket, b"\x81\x03bob").await;
}

#[tokio::test]
async fn a_revoked_session_closes_its_streams_and_leaves_the_others_of_the_subject() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    let (mut bob_socket, _bob_head) = harness.websocket(Some("bob")).await;
    let revoked =
        snapshot_at(8, &SUBJECTS).with_revoked_session(SessionId::new("session-alice").unwrap());

    harness
        .apply(revoked, &["revocation/session/session-alice".to_owned()])
        .await;

    the_stream_ended_with_the_frame(&mut socket, 1008).await;
    echo(&mut bob_socket, b"\x81\x03bob").await;
}

#[tokio::test]
async fn a_user_cutoff_closes_the_streams_of_the_user_only() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    let (mut bob_socket, _bob_head) = harness.websocket(Some("bob")).await;
    let cutoff = UserRevocationState {
        user: user_id(0),
        tokens_valid_after_micros: micros(NOW).unwrap(),
        prune_after_micros: micros(NOW.saturating_add(3_600)).unwrap(),
    };
    let revoked = snapshot_at(8, &SUBJECTS).with_user_cutoff(cutoff);

    harness
        .apply(revoked, &[format!("revocation/user/{}", user_id(0))])
        .await;

    the_stream_ended_with_the_frame(&mut socket, 1008).await;
    echo(&mut bob_socket, b"\x81\x03bob").await;
}

#[tokio::test]
async fn a_global_cutoff_decides_every_stream_again_and_closes_them_all() {
    let harness = Harness::start(8).await;
    let (mut alice_socket, _alice_head) = harness.websocket(Some("alice")).await;
    let (mut bob_events, _bob_head) = harness.events(Some("bob")).await;
    read_until(&mut bob_events, b"data: hello\n\n").await;
    let revoked = snapshot_at(8, &SUBJECTS).with_global_cutoff(GlobalRevocationState {
        tokens_valid_after_micros: micros(NOW).unwrap(),
    });

    harness
        .apply(revoked, &["revocation/global".to_owned()])
        .await;

    the_stream_ended_with_the_frame(&mut alice_socket, 1008).await;
    the_event_stream_ended(&mut bob_events).await;
    assert!(harness.streams.registry().is_empty());
}

#[tokio::test]
async fn an_untouched_version_leaves_every_stream_open_and_still_finishes() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;

    harness.apply(snapshot_at(8, &SUBJECTS), &[]).await;

    assert_eq!(harness.board.finished(), 8);
    echo(&mut socket, b"\x81\x02hi").await;
}

/// The grant of alice's stream as the pipeline would have recorded it on version 7.
fn alice_stream(streams: &Streams) -> StreamHandle {
    let principal = Principal::from(TokenIdentity::from(&token_of(0, &ALICE)));
    let record = StreamRecord {
        subject: Some(user_id(0).to_string()),
        session: Some("session-alice".to_owned()),
        required_keys: vec![WS_KEY.to_owned()],
        scope: "global".to_owned(),
        token_expires_at: Some(principal.expires_at()),
        assignment_expires_at: None,
        version: 7,
        route: None,
        service: None,
    };
    let grant = Grant {
        principal: Some(principal),
        host: HOST.to_owned(),
        method: HttpMethod::Get,
        path: "/ws".to_owned(),
    };
    streams.registry().open(record, grant).unwrap()
}

#[tokio::test]
async fn a_stream_registered_after_the_version_finished_is_evaluated_against_it_at_once() {
    let harness = Harness::start(8).await;
    harness.apply(snapshot_at(8, &without_alice()), &[]).await;
    let late = alice_stream(&harness.streams);

    harness.streams.admit(late.id()).await;

    assert_eq!(late.closed().await, CloseReason::Revoked);
    assert!(harness.streams.registry().is_empty());
}

fn without_alice() -> [&'static Subject; 3] {
    [&BOB, &CAROL, &DAVE]
}

#[tokio::test]
async fn the_record_waits_for_a_stream_registered_below_the_version_that_is_still_unchecked() {
    let harness = Harness::start(8).await;
    let waiting = alice_stream(&harness.streams);

    harness.apply(snapshot_at(8, &without_alice()), &[]).await;

    assert_eq!(
        waiting.closed().await,
        CloseReason::Revoked,
        "the stream was decided against the version before the record reached it"
    );
    assert_eq!(harness.board.finished(), 8);
}

#[tokio::test]
async fn a_slow_hook_never_stalls_the_versions_that_follow_and_the_record_advances_in_order() {
    let harness = Harness::start(8).await;
    let (mut socket, _head) = harness.websocket(Some("alice")).await;
    for version in 8..=20 {
        harness.moving.publish(snapshot_at(version, &SUBJECTS));
        harness.board.submit(PolicyChange {
            version: PolicyVersion::new(version).unwrap(),
            touch: PolicyTouch::nothing(),
        });
    }

    tokio::time::timeout(
        BOUND,
        harness.board.reached(PolicyVersion::new(20).unwrap()),
    )
    .await
    .unwrap();

    assert_eq!(harness.board.finished(), 20);
    echo(&mut socket, b"\x81\x02hi").await;
}
