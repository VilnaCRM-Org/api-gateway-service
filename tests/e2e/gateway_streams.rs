//! The in-process gateway of the stream scenarios (Story 11.1): the production pipeline, stream
//! registry and [`HyperUpstreamForwarder`] over a snapshot that the scenario describes, served on a
//! loopback socket, in front of a fake upstream that echoes WebSocket bytes and serves one event.
//! Tokens, assignments and the proof of freshness run on clocks that the scenario moves forward.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use iam_application::{EndpointDirectory, FreshnessState, RequestAuthorizer, ZoneSource};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CatalogueEntryState, CompiledRoleSet, EndpointConditions,
    EndpointParts, EndpointSlice, FreshnessRule, GrantStatus, HttpMethod, PermissionGrant,
    PolicyVersion, PolicyView, RevocationView, RoleId, RouteFlag, RouteFlags, RouteState,
    ServiceName, SessionId, SubjectId, SubjectRef, TokenId, TokenMemo, TokenRepository,
    UpstreamEndpoint, UpstreamState, WatchTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings,
};
use service::bootstrap::gateway::pipeline::{Forwarder, Pipeline, UnauditedCommands, router};
use service::bootstrap::gateway::streams::{PodFence, StreamSettings, Streams, close_frame};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::ManualClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::rng::FakeRng;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// The instant the pipeline sees as now, in seconds after the epoch.
const NOW: u64 = 1_800_000_000;

/// The hard bound of the freshness rule of the gateway.
const HARD_BOUND: Duration = Duration::from_secs(15);

/// How long a scenario waits for the gateway to answer or to close a stream.
const BOUND: Duration = Duration::from_secs(10);

const HOST: &str = "api.example.test";
const WS_KEY: &str = "rest:streams:GET /ws";
const EVENTS_KEY: &str = "rest:streams:GET /events";

/// What a scenario describes before the first stream: the subjects and the assignments that grant
/// them the keys of the two streaming routes (`None` never expires).
#[derive(Debug, Default)]
pub(crate) struct StreamsPlan {
    subjects: Vec<(String, Vec<Option<u64>>)>,
}

impl StreamsPlan {
    /// Adds an assignment of `name` that grants the keys and expires in `seconds`, or never.
    pub(crate) fn assign(&mut self, name: &str, seconds: Option<u64>) {
        if let Some((_, held)) = self.subjects.iter_mut().find(|(known, _)| known == name) {
            held.push(seconds);
        } else {
            self.subjects.push((name.to_owned(), vec![seconds]));
        }
    }

    /// Adds the subject `name` without a key.
    pub(crate) fn without_key(&mut self, name: &str) {
        if self.subjects.iter().all(|(known, _)| known != name) {
            self.subjects.push((name.to_owned(), Vec::new()));
        }
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .expect("a representable instant")
}

fn user_id(index: usize) -> Uuid {
    Uuid::parse(&format!(
        "3d9b7c1e-5a2f-4e8d-b6c0-{:012x}",
        index.saturating_add(1)
    ))
    .expect("a valid user id")
}

fn role_id(subject: usize, assignment: usize) -> RoleId {
    RoleId::parse(&format!(
        "0190f2a8-7b3c-7d4e-8f10-{:06x}{:06x}",
        subject.saturating_add(1),
        assignment.saturating_add(1)
    ))
    .expect("a valid role id")
}

fn token_of(index: usize, name: &str) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(user_id(index)),
        session: Some(SessionId::new(&format!("session-{name}")).expect("a session")),
        token_id: TokenId::new(&format!("token-{name}")).expect("a token id"),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 900),
    })
}

fn micros(seconds: u64) -> Option<i64> {
    i64::try_from(seconds.saturating_mul(1_000_000)).ok()
}

/// The snapshot of the plan: the two streaming routes of the service `streams`, its catalogue and
/// the roles and assignments of every subject.
fn snapshot(plan: &StreamsPlan) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let streams = UpstreamState::of(upstream(&mut rng, "streams", "streams").parts());
    let flags = RouteFlags::default().with(RouteFlag::Streaming, true);
    let entries = [WS_KEY, EVENTS_KEY]
        .map(|key| CatalogueEntryState::untyped(key.to_owned(), [false, false]))
        .to_vec();
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(7).expect("a version"))
        .with_upstream(streams.clone())
        .with_catalogue(
            ServiceName::new("streams").expect("a service name"),
            entries,
        );
    for path in ["/ws", "/events"] {
        let mut draft = route_draft(HOST, path, &[HttpMethod::Get], "streams", streams.id);
        draft.flags = flags;
        snapshot = snapshot.with_route(RouteState::of(route(&mut rng, &draft).parts()));
    }
    for (index, (_, held)) in plan.subjects.iter().enumerate() {
        snapshot = with_subject(snapshot, index, held);
    }
    snapshot
}

fn with_subject(snapshot: GatewaySnapshot, index: usize, held: &[Option<u64>]) -> GatewaySnapshot {
    let grants = [WS_KEY, EVENTS_KEY].map(|key| {
        (
            PermissionGrant::parse(key).expect("a permission key"),
            GrantStatus::Active,
        )
    });
    let mut snapshot = snapshot;
    let mut assignments = Vec::new();
    for (number, expires) in held.iter().enumerate() {
        let role = role_id(index, number);
        assignments.push(AssignmentState {
            role,
            scope: AssignmentScope::Global,
            expires_at_micros: expires.and_then(|seconds| micros(NOW.saturating_add(seconds))),
        });
        snapshot = snapshot.with_role_set(role, CompiledRoleSet::compile(grants.clone()));
    }
    snapshot.with_assignments(SubjectRef::user(user_id(index)), assignments)
}

/// The directory whose only endpoint for the service `streams` is `address`.
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

#[expect(
    clippy::disallowed_methods,
    reason = "an end-to-end scenario serves on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free loopback port")
}

/// The head of a request or an answer, read up to the empty line.
async fn read_head(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    tokio::time::timeout(BOUND, async {
        while !head.ends_with(b"\r\n\r\n") {
            match socket.read_u8().await {
                Ok(byte) => head.push(byte),
                Err(_closed) => break,
            }
        }
    })
    .await
    .expect("the head arrives in time");
    String::from_utf8_lossy(&head).into_owned()
}

/// One connection of the fake upstream: `/ws` is answered `101` and echoed, `/events` is answered
/// with one event and then left open until the gateway goes away.
async fn upstream_connection(mut socket: TcpStream, seen: Arc<AtomicUsize>) {
    let head = read_head(&mut socket).await;
    seen.fetch_add(1, Ordering::SeqCst);
    let mut parts = head.split_whitespace();
    let target = parts.nth(1).unwrap_or_default();
    if target == "/ws" {
        let answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: c3RyZWFtcw==\r\n\r\n";
        drop(socket.write_all(answer.as_bytes()).await);
        let (mut reader, mut writer) = socket.split();
        drop(tokio::io::copy(&mut reader, &mut writer).await);
    } else {
        let answer = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: hello\n\n\r\n";
        drop(socket.write_all(answer.as_bytes()).await);
        let mut rest = Vec::new();
        drop(socket.read_to_end(&mut rest).await);
    }
}

async fn serve_upstream(seen: Arc<AtomicUsize>) -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().expect("a bound address");
    drop(tokio::spawn(async move {
        while let Ok((socket, _peer)) = listener.accept().await {
            drop(tokio::spawn(upstream_connection(socket, Arc::clone(&seen))));
        }
    }));
    address
}

/// The pipeline over `view` that forwards through `forwarder` and verifies the tokens of `plan`.
fn pipeline_over(
    plan: &StreamsPlan,
    view: &Arc<dyn PolicyView>,
    freshness: &Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
    forwarder: Arc<Forwarder>,
) -> Pipeline {
    let verifier = plan.subjects.iter().enumerate().fold(
        FakeAccessTokenVerifier::new(),
        |verifier, (index, (name, _))| {
            verifier.accepting(&format!("{name}.token.value"), token_of(index, name))
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

/// The gateway of a scenario, with the connections of its subjects.
#[derive(Debug)]
pub(crate) struct StreamsHarness {
    address: SocketAddr,
    upstream_requests: Arc<AtomicUsize>,
    streams: Arc<Streams>,
    clock: Arc<ManualClock>,
    boot: Arc<FakeBootClock>,
    sockets: HashMap<String, TcpStream>,
    answers: HashMap<String, u16>,
    _stop: watch::Sender<bool>,
}

impl StreamsHarness {
    /// Serves the fake upstream and the gateway of `plan` in front of it.
    pub(crate) async fn start(plan: &StreamsPlan) -> Self {
        let upstream_requests = Arc::new(AtomicUsize::new(0));
        let upstream_address = serve_upstream(Arc::clone(&upstream_requests)).await;
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
            PolicyVersion::new(7).expect("a version"),
        );
        let clock = Arc::new(ManualClock::at(at(NOW)));
        let policy_clock: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
        let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::serving(snapshot(plan)));
        let streams = Streams::new(
            StreamSettings {
                idle_timeout: Duration::from_mins(5),
                per_subject: 32,
            },
            Arc::clone(&policy_clock),
        );
        let pipeline = pipeline_over(plan, &view, &freshness, &policy_clock, forwarder)
            .with_streams(Arc::clone(&streams));
        let (stop, stopping) = watch::channel(false);
        let fence = Arc::new(PodFence::new(view, freshness));
        drop(tokio::spawn(Arc::clone(&streams).watch(fence, stopping)));
        let listener = bound().await;
        let address = listener.local_addr().expect("a bound address");
        let gateway = router(pipeline);
        drop(tokio::spawn(
            async move { axum::serve(listener, gateway).await },
        ));
        Self {
            address,
            upstream_requests,
            streams,
            clock,
            boot,
            sockets: HashMap::new(),
            answers: HashMap::new(),
            _stop: stop,
        }
    }

    /// How many requests reached the fake upstream.
    pub(crate) fn upstream_requests(&self) -> usize {
        self.upstream_requests.load(Ordering::SeqCst)
    }

    /// How many streams of the subject `name` the registry holds.
    pub(crate) fn held_by(&self, name: &str) -> usize {
        self.streams
            .registry()
            .held_by_session(&format!("session-{name}"))
    }

    /// Opens a WebSocket (`kind` is `ws`) or an event stream (`events`) for `name`, or without a
    /// token when `name` is `None`, and keeps the connection and the status of the answer.
    #[expect(
        clippy::disallowed_methods,
        reason = "an end-to-end scenario connects to the gateway it started on loopback"
    )]
    pub(crate) async fn open(&mut self, name: Option<&str>, kind: &str) {
        let mut socket = TcpStream::connect(self.address)
            .await
            .expect("the gateway accepts");
        socket
            .write_all(request_text(name, kind).as_bytes())
            .await
            .expect("the request is written");
        let head = read_head(&mut socket).await;
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|status| status.parse().ok())
            .expect("a status line");
        let key = connection_key(name, kind);
        self.answers.insert(key.clone(), status);
        self.sockets.insert(key, socket);
    }

    /// The status with which the gateway answered the opening request of that connection.
    pub(crate) fn answer(&self, name: Option<&str>, kind: &str) -> u16 {
        *self
            .answers
            .get(&connection_key(name, kind))
            .expect("the scenario opened that stream")
    }

    /// Sends `frame` over the WebSocket of `name` and reads it back.
    pub(crate) async fn echo(&mut self, name: &str, frame: &[u8]) {
        let socket = self.socket(name, "ws");
        socket.write_all(frame).await.expect("the frame is written");
        let mut back = vec![0_u8; frame.len()];
        tokio::time::timeout(BOUND, socket.read_exact(&mut back))
            .await
            .expect("the frame comes back in time")
            .expect("the frame comes back");
        assert_eq!(back, frame);
    }

    /// Reads from the event stream of `name` until its first event arrived.
    pub(crate) async fn first_event(&mut self, name: &str) {
        let socket = self.socket(name, "events");
        let mut seen = Vec::new();
        tokio::time::timeout(BOUND, async {
            let mut chunk = [0_u8; 128];
            while !seen.ends_with(b"data: hello\n\n\r\n") {
                let read = socket.read(&mut chunk).await.expect("the stream is read");
                assert_ne!(read, 0, "the stream ended before its first event");
                seen.extend_from_slice(&chunk[..read]);
            }
        })
        .await
        .expect("the event arrives in time");
    }

    /// Reads the WebSocket of `name` to its end and expects the close frame with `code`.
    pub(crate) async fn expect_closed(&mut self, name: &str, code: u16) {
        let rest = self.read_to_end(name, "ws").await;
        assert_eq!(rest, close_frame(code));
    }

    /// Reads the event stream of `name` to its end and expects the chunked body to be complete.
    pub(crate) async fn expect_ended(&mut self, name: &str) {
        let rest = self.read_to_end(name, "events").await;
        assert!(rest.ends_with(b"0\r\n\r\n"), "the body ended: {rest:?}");
    }

    /// Moves the clock of tokens and assignments forward.
    pub(crate) fn pass(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// Ages the proof of the pod past the hard bound.
    pub(crate) fn age_proof(&self) {
        self.boot
            .advance(HARD_BOUND.saturating_add(Duration::from_secs(1)));
    }

    fn socket(&mut self, name: &str, kind: &str) -> &mut TcpStream {
        self.sockets
            .get_mut(&connection_key(Some(name), kind))
            .expect("the scenario opened that stream")
    }

    async fn read_to_end(&mut self, name: &str, kind: &str) -> Vec<u8> {
        let socket = self.socket(name, kind);
        let mut rest = Vec::new();
        tokio::time::timeout(BOUND, socket.read_to_end(&mut rest))
            .await
            .expect("the gateway ends the stream in time")
            .expect("the stream is read");
        rest
    }
}

fn connection_key(name: Option<&str>, kind: &str) -> String {
    format!("{}/{kind}", name.unwrap_or("-"))
}

fn request_text(name: Option<&str>, kind: &str) -> String {
    let mut text = format!("GET /{kind} HTTP/1.1\r\nHost: {HOST}\r\n");
    if kind == "ws" {
        text.push_str(
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        );
    } else {
        text.push_str("Accept: text/event-stream\r\nConnection: close\r\n");
    }
    if let Some(name) = name {
        text.push_str(&["Authorization: Bearer ", name, ".token.value\r\n"].concat());
    }
    text.push_str("\r\n");
    text
}
