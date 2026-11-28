//! GraphQL subscriptions over WebSocket through the gateway (Story 11.3): the production pipeline,
//! the stream registry and the `HyperUpstreamForwarder` in front of a fake upstream that speaks
//! `graphql-transport-ws` and `graphql-ws`, served on loopback sockets. Tokens and assignments run
//! on a controlled clock that a test moves forward.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::Request;
use futures_util::{SinkExt as _, StreamExt as _};
use iam_application::{
    AuditGate, EndpointDirectory, FreshnessState, GraphQlRequestAnalyzer, ParseBudgetSettings,
    ReevaluationBoard, RequestAuthorizer, StreamReauthorizer, ZoneSource,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CatalogueEntryState, CompiledRoleSet, DocumentCache,
    EndpointConditions, EndpointParts, EndpointSlice, FreshnessRule, GrantStatus, HttpMethod,
    PermissionGrant, PolicyChange, PolicySnapshot, PolicyTouch, PolicyVersion, PolicyView,
    RevocationView, RoleId, RouteFlag, RouteFlags, RouteState, ServiceName, SessionId, StateKey,
    SubjectId, SubjectRef, TokenId, TokenMemo, TokenRejection, TokenRepository, UpstreamEndpoint,
    UpstreamState, WatchTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, DocumentCacheSettings, MokaDocumentCache, MokaTokenMemo,
    SnapshotRevocationView, TokenMemoSettings,
};
use serde_json::{Value, json};
use service::bootstrap::gateway::graphql_ws::SocketSettings;
use service::bootstrap::gateway::pipeline::{
    ClientAddress, Forwarder, Pipeline, UnauditedCommands, router,
};
use service::bootstrap::gateway::streams::{PodFence, StreamSettings, Streams};
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
use test_support::upstream::upstream_forwarding;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::{WebSocketStream, client_async};
use tower::ServiceExt as _;

const HOST: &str = "api.example.test";
const NOW: u64 = 1_800_000_000;
const HARD_BOUND: Duration = Duration::from_secs(15);
const BOUND: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(400);

const ROUTE_KEY: &str = "rest:orders:GET /graphql";
const LEDGER_KEY: &str = "rest:orders:GET /ledger";
const ORDER_UPDATED: &str = "gql:orders:Subscription.orderUpdated";
const PAYMENT_UPDATED: &str = "gql:orders:Subscription.paymentUpdated";
const CANCEL: &str = "gql:orders:Mutation.cancel";
const AUDITED_ROUTE: &str = "rest:orders:GET /audited";
const AUDITED_UPDATED: &str = "gql:orders:Subscription.auditedUpdated";

const TRANSPORT: &str = "graphql-transport-ws";
const LEGACY: &str = "graphql-ws";

/// A subject of the scenarios: how long its token lives, the keys its role grants for good and
/// the keys that a second role grants until `expiring_seconds` after the start.
struct Subject {
    name: &'static str,
    token_seconds: u64,
    grants: &'static [&'static str],
    expiring: &'static [&'static str],
    expiring_seconds: u64,
}

const ERIN: Subject = Subject {
    name: "erin",
    token_seconds: 900,
    grants: &[ROUTE_KEY, LEDGER_KEY, ORDER_UPDATED],
    expiring: &[],
    expiring_seconds: 0,
};
const FRANK: Subject = Subject {
    name: "frank",
    token_seconds: 900,
    grants: &[ORDER_UPDATED],
    expiring: &[],
    expiring_seconds: 0,
};
const GWEN: Subject = Subject {
    name: "gwen",
    token_seconds: 900,
    grants: &[ROUTE_KEY],
    expiring: &[ORDER_UPDATED],
    expiring_seconds: 600,
};
const HANA: Subject = Subject {
    name: "hana",
    token_seconds: 900,
    grants: &[ROUTE_KEY, ORDER_UPDATED, PAYMENT_UPDATED, CANCEL],
    expiring: &[],
    expiring_seconds: 0,
};
const IVY: Subject = Subject {
    name: "ivy",
    token_seconds: 900,
    grants: &[ROUTE_KEY, AUDITED_ROUTE, AUDITED_UPDATED],
    expiring: &[],
    expiring_seconds: 0,
};
const SUBJECTS: [&Subject; 5] = [&ERIN, &FRANK, &GWEN, &HANA, &IVY];

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

fn role_id(index: usize) -> RoleId {
    RoleId::parse(&format!(
        "0190f2a8-7b3c-7d4e-8f10-{:012x}",
        index.saturating_add(1)
    ))
    .unwrap()
}

fn micros(seconds: u64) -> Option<i64> {
    i64::try_from(seconds.saturating_mul(1_000_000)).ok()
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

fn index_of(name: &str) -> usize {
    SUBJECTS
        .iter()
        .position(|subject| subject.name == name)
        .unwrap()
}

/// What the fake upstream saw.
#[derive(Debug, Default)]
struct Seen {
    connections: AtomicUsize,
    messages: Mutex<Vec<Value>>,
}

impl Seen {
    fn messages(&self) -> Vec<Value> {
        self.messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn of_type(&self, kind: &str) -> Vec<Value> {
        self.messages()
            .into_iter()
            .filter(|message| message["type"] == kind)
            .collect()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// The head of an HTTP request, read up to the empty line.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

fn header_of<'head>(head: &'head str, name: &str) -> Option<&'head str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// A fake upstream that speaks both protocols: it acknowledges `connection_init` and records
/// every message it reads.
async fn fake_upstream(seen: Arc<Seen>) -> SocketAddr {
    let listener = bound().await;
    let address = listener.local_addr().unwrap();
    drop(tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            drop(tokio::spawn(converse(stream, Arc::clone(&seen))));
        }
    }));
    address
}

/// What the fake upstream sends after it read `message`, and whether it then hangs up. A
/// `connection_init` payload member `mode` and the words after `#` in the document of an
/// operation script the answer.
fn replies_to(message: &Value) -> (Vec<Message>, bool) {
    let ack = Message::text(json!({ "type": "connection_ack" }).to_string());
    let id = message["id"].clone();
    let text = |value: Value| Message::text(value.to_string());
    match message["type"].as_str() {
        Some("connection_init") => match message["payload"]["mode"].as_str() {
            Some("silent") => (Vec::new(), false),
            Some("other") => (vec![text(json!({ "type": "ka" }))], false),
            Some("ping-first") => (vec![Message::Ping(Bytes::new()), ack], false),
            Some("close") => (vec![Message::Close(None)], false),
            _ => (vec![ack], false),
        },
        Some("subscribe" | "start") => {
            let query = message["payload"]["query"].as_str().unwrap_or_default();
            let mut replies = Vec::new();
            if query.contains("next") {
                replies.push(text(json!({ "type": "next", "id": id, "payload": {} })));
            }
            if query.contains("binary") {
                replies.push(Message::Binary(Bytes::from_static(&[1, 2, 3])));
            }
            if query.contains("ping") {
                replies.push(Message::Ping(Bytes::new()));
            }
            if query.contains("complete") {
                replies.push(text(json!({ "type": "complete", "id": id })));
            }
            if query.contains("close") {
                replies.push(Message::Close(None));
            }
            (replies, query.contains("hangup"))
        }
        _ => (Vec::new(), false),
    }
}

async fn converse(mut stream: TcpStream, seen: Arc<Seen>) {
    let head = read_head(&mut stream).await;
    seen.connections.fetch_add(1, Ordering::SeqCst);
    let mut key = header_of(&head, "sec-websocket-key").unwrap().to_owned();
    if header_of(&head, "x-upstream-mode") == Some("bad-accept") {
        "another key".clone_into(&mut key);
    }
    let protocol = header_of(&head, "sec-websocket-protocol")
        .unwrap_or_default()
        .to_owned();
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    stream.write_all(answer.as_bytes()).await.unwrap();
    let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    while let Some(Ok(message)) = socket.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let decoded: Value = serde_json::from_str(text.as_str()).unwrap();
        let (replies, hangup) = replies_to(&decoded);
        seen.messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(decoded);
        for reply in replies {
            socket.send(reply).await.unwrap();
        }
        if hangup {
            return;
        }
    }
}

fn field(key: &str) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
        return_type: Some("String".to_owned()),
        possible_types: Vec::new(),
    }
}

/// The snapshot at `version` in which every subject holds the keys that `grants` names for it.
fn snapshot_at<'grants>(
    version: i64,
    grants: impl Fn(&Subject) -> &'grants [&'grants str],
) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let orders =
        UpstreamState::of(upstream_forwarding(&mut rng, "orders", "orders", false).parts());
    let ledger = UpstreamState::of(upstream_forwarding(&mut rng, "ledger", "orders", true).parts());
    let flags = RouteFlags::default()
        .with(RouteFlag::Streaming, true)
        .with(RouteFlag::Graphql, true);
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(version).unwrap())
        .with_upstream(orders.clone())
        .with_upstream(ledger.clone())
        .with_catalogue(
            ServiceName::new("orders").unwrap(),
            vec![
                CatalogueEntryState::untyped(ROUTE_KEY.to_owned(), [false, false]),
                CatalogueEntryState::untyped(LEDGER_KEY.to_owned(), [false, false]),
                field(ORDER_UPDATED),
                field(PAYMENT_UPDATED),
                field(CANCEL),
                CatalogueEntryState::untyped(AUDITED_ROUTE.to_owned(), [false, true]),
                CatalogueEntryState {
                    audit_always: true,
                    ..field(AUDITED_UPDATED)
                },
            ],
        );
    for (path, upstream) in [
        ("/graphql", &orders),
        ("/ledger", &ledger),
        ("/audited", &orders),
    ] {
        let mut draft = route_draft(HOST, path, &[HttpMethod::Get], "orders", upstream.id);
        draft.flags = flags;
        snapshot = snapshot.with_route(RouteState::of(route(&mut rng, &draft).parts()));
    }
    for (index, subject) in SUBJECTS.iter().enumerate() {
        let mut held = Vec::new();
        for (number, (keys, expires)) in [
            (grants(subject), None),
            (subject.expiring, Some(subject.expiring_seconds)),
        ]
        .into_iter()
        .enumerate()
        {
            if keys.is_empty() {
                continue;
            }
            let compiled = CompiledRoleSet::compile(
                keys.iter()
                    .map(|key| (PermissionGrant::parse(key).unwrap(), GrantStatus::Active)),
            );
            let role = role_id(index.saturating_mul(2).saturating_add(number));
            snapshot = snapshot.with_role_set(role, compiled);
            held.push(AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: expires.and_then(|seconds| micros(NOW.saturating_add(seconds))),
            });
        }
        snapshot = snapshot.with_assignments(SubjectRef::user(user_id(index)), held);
    }
    snapshot
}

fn snapshot() -> GatewaySnapshot {
    snapshot_at(7, |subject| subject.grants)
}

/// A policy view whose snapshot a test replaces, as the apply thread publishes a version.
#[derive(Debug)]
struct Moving(Mutex<Arc<dyn PolicySnapshot>>);

impl PolicyView for Moving {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        Some(Arc::clone(
            &self.0.lock().unwrap_or_else(PoisonError::into_inner),
        ))
    }
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
    for service in ["orders-service", "ledger-service"] {
        directory.replace(
            &WatchTarget {
                namespace: "platform".to_owned(),
                service: service.to_owned(),
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
    }
    directory
}

/// The gateway of a scenario and what a test moves.
struct Harness {
    address: SocketAddr,
    seen: Arc<Seen>,
    streams: Arc<Streams>,
    clock: Arc<ManualClock>,
    moving: Arc<Moving>,
    board: Arc<ReevaluationBoard>,
    pipeline: Pipeline,
    _stop: watch::Sender<bool>,
}

/// What a scenario changes in the gateway it runs against.
#[derive(Clone, Copy)]
struct Options {
    init_timeout: Duration,
    budget: ParseBudgetSettings,
    /// The capacity of the audit lane when the gateway runs audit-or-deny.
    audit_capacity: Option<usize>,
}

impl Options {
    fn timeout(init_timeout: Duration) -> Self {
        Self {
            init_timeout,
            budget: ParseBudgetSettings::default(),
            audit_capacity: None,
        }
    }
}

/// Puts the address of a client on every request, as the accept loop of the service does.
async fn with_client_address(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request
        .extensions_mut()
        .insert(ClientAddress::from(SocketAddr::from((
            [203, 0, 113, 9],
            50_000,
        ))));
    next.run(request).await
}

impl Harness {
    async fn start(init_timeout: Duration) -> Self {
        Self::start_with(Options::timeout(init_timeout)).await
    }

    async fn start_with(options: Options) -> Self {
        let seen = Arc::new(Seen::default());
        let upstream_address = fake_upstream(Arc::clone(&seen)).await;
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
        let moving = Arc::new(Moving(Mutex::new(Arc::new(snapshot()))));
        let view: Arc<dyn PolicyView> = Arc::<Moving>::clone(&moving);
        let streams = Streams::new(
            StreamSettings {
                idle_timeout: Duration::from_mins(5),
                per_subject: 8,
            },
            Arc::<ManualClock>::clone(&clock),
        );
        let policy_clock: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
        let pipeline = pipeline_over(&view, &freshness, &policy_clock, forwarder, options)
            .with_streams(Arc::clone(&streams))
            .with_graphql_ws(SocketSettings {
                init_timeout: options.init_timeout,
            });
        let served = pipeline.clone();
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
        let listener = bound().await;
        let address = listener.local_addr().unwrap();
        drop(tokio::spawn(async move {
            axum::serve(
                listener,
                router(pipeline).layer(axum::middleware::from_fn(with_client_address)),
            )
            .await
        }));
        Self {
            address,
            seen,
            streams,
            clock,
            moving,
            board,
            pipeline: served,
            _stop: stop,
        }
    }

    /// Publishes `snapshot` and hands the apply thread's report of it, with what it touched, to
    /// the re-authorization; completes once that has decided the streams of the version.
    async fn apply(&self, snapshot: GatewaySnapshot, touched: &[String]) {
        let version = snapshot.version();
        *self.moving.0.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(snapshot);
        let mut touch = PolicyTouch::nothing();
        for key in touched {
            touch.note(&StateKey::parse(key).unwrap());
        }
        self.board.submit(PolicyChange { version, touch });
        tokio::time::timeout(BOUND, self.board.reached(version))
            .await
            .unwrap();
    }

    /// Upgrades a socket on `path` offering `protocols`, with the token of `subject` in the
    /// upgrade request when there is one.
    async fn connect(
        &self,
        path: &str,
        protocols: &str,
        subject: Option<&str>,
    ) -> Result<Socket, WsError> {
        self.connect_with(path, protocols, subject, &[]).await
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "an integration test connects to the gateway it started on loopback"
    )]
    async fn connect_with(
        &self,
        path: &str,
        protocols: &str,
        subject: Option<&str>,
        headers: &[(&'static str, &str)],
    ) -> Result<Socket, WsError> {
        let mut request = format!("ws://{HOST}{path}").into_client_request().unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(*name, value.parse().unwrap());
        }
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", protocols.parse().unwrap());
        if let Some(subject) = subject {
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {subject}.token.value").parse().unwrap(),
            );
        }
        let stream = TcpStream::connect(self.address).await.unwrap();
        let (socket, response) = client_async(request, stream).await?;
        assert_eq!(
            response.headers().get("sec-websocket-protocol").unwrap(),
            protocols.split(',').next().unwrap().trim()
        );
        Ok(Socket(socket))
    }

    async fn socket(&self, protocol: &str, subject: Option<&str>) -> Socket {
        self.connect("/graphql", protocol, subject).await.unwrap()
    }

    /// A socket that is initialised and acknowledged.
    async fn acknowledged(&self, protocol: &str, subject: &str) -> Socket {
        let mut socket = self.socket(protocol, Some(subject)).await;
        socket.init(None).await;
        assert_eq!(socket.next_text().await["type"], "connection_ack");
        socket
    }
}

fn pipeline_over(
    view: &Arc<dyn PolicyView>,
    freshness: &Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
    forwarder: Arc<Forwarder>,
    options: Options,
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
    let verifier: Arc<dyn AccessTokenVerifier> =
        Arc::new(verifier.rejecting("unavailable.token.value", TokenRejection::Unavailable));
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
    let cache: Arc<dyn DocumentCache> = Arc::new(MokaDocumentCache::new(DocumentCacheSettings {
        capacity_bytes: 1 << 20,
        time_to_idle: Duration::from_mins(1),
    }));
    let analyzer = GraphQlRequestAnalyzer::new(cache, options.budget);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    )
    .with_graphql(Arc::new(analyzer));
    let authorizer = match options.audit_capacity {
        Some(capacity) => authorizer.with_audit_gate(Arc::new(AuditGate::new(
            Arc::clone(clock),
            Duration::from_mins(1),
            capacity,
        ))),
        None => authorizer,
    };
    Pipeline::new(
        Arc::clone(view),
        Arc::clone(freshness),
        tokens,
        Arc::new(authorizer),
        forwarder,
    )
}

/// The client end of a socket.
struct Socket(WebSocketStream<TcpStream>);

impl Socket {
    async fn send(&mut self, message: &Value) {
        self.send_text(message.to_string()).await;
    }

    async fn send_text(&mut self, text: String) {
        self.0.send(Message::text(text)).await.unwrap();
    }

    async fn init(&mut self, payload: Option<Value>) {
        let message = payload.map_or_else(
            || json!({ "type": "connection_init" }),
            |payload| json!({ "type": "connection_init", "payload": payload }),
        );
        self.send(&message).await;
    }

    /// Starts the operation `id`: `subscribe` on the transport protocol, `start` on the legacy.
    async fn operation(&mut self, protocol: &str, id: &str, document: &str) {
        let kind = if protocol == TRANSPORT {
            "subscribe"
        } else {
            "start"
        };
        self.send(&json!({ "id": id, "type": kind, "payload": { "query": document } }))
            .await;
    }

    /// The next message, skipping the control frames.
    async fn next(&mut self) -> Message {
        tokio::time::timeout(BOUND, async {
            loop {
                match self.0.next().await {
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(message)) => return message,
                    Some(Err(error)) => panic!("the socket failed: {error}"),
                    None => panic!("the socket ended"),
                }
            }
        })
        .await
        .unwrap()
    }

    async fn next_text(&mut self) -> Value {
        match self.next().await {
            Message::Text(text) => serde_json::from_str(text.as_str()).unwrap(),
            Message::Binary(_)
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::Close(_)
            | Message::Frame(_) => panic!("not a text message"),
        }
    }

    async fn frame(&mut self, message: Message) {
        self.0.send(message).await.unwrap();
    }

    /// Reads until the socket has ended, whichever way.
    async fn ended(&mut self) {
        tokio::time::timeout(BOUND, async {
            while let Some(Ok(_)) = self.0.next().await {}
        })
        .await
        .unwrap();
    }

    /// The code the socket was closed with.
    async fn closed_with(&mut self) -> u16 {
        match self.next().await {
            Message::Close(Some(frame)) => u16::from(frame.code),
            Message::Text(_)
            | Message::Binary(_)
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::Close(None)
            | Message::Frame(_) => panic!("not a close frame"),
        }
    }

    /// Proves the socket is open and answering: a ping of the protocol gets its pong.
    async fn still_open(&mut self) {
        self.send(&json!({ "type": "ping" })).await;
        assert_eq!(self.next_text().await["type"], "pong");
    }
}

async fn wait_for(condition: impl Fn() -> bool + Send + Sync) {
    tokio::time::timeout(BOUND, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

const ORDER_DOCUMENT: &str = "subscription { orderUpdated }";
const PAYMENT_DOCUMENT: &str = "subscription { paymentUpdated }";

fn error_code(message: &Value) -> &Value {
    let payload = &message["payload"];
    payload
        .get(0)
        .map_or(&payload["extensions"]["code"], |first| {
            &first["extensions"]["code"]
        })
}

#[tokio::test]
async fn the_two_subprotocols_are_upgraded_and_any_other_is_refused_before_the_upgrade() {
    let harness = Harness::start(BOUND).await;

    let transport = harness.connect("/graphql", TRANSPORT, Some("erin")).await;
    let legacy = harness.connect("/graphql", LEGACY, Some("erin")).await;
    let other = harness.connect("/graphql", "chat", Some("erin")).await;

    assert!(transport.is_ok());
    assert!(legacy.is_ok());
    let Err(WsError::Http(refused)) = other else {
        panic!("the other subprotocol was upgraded");
    };
    assert_eq!(refused.status(), 400);
    assert_eq!(harness.seen.connections(), 0);
}

#[tokio::test]
async fn a_token_in_connection_init_authenticates_and_a_bad_or_missing_one_closes_with_4401() {
    let harness = Harness::start(BOUND).await;
    let mut valid = harness.socket(TRANSPORT, None).await;
    let mut invalid = harness.socket(TRANSPORT, None).await;
    let mut missing = harness.socket(TRANSPORT, None).await;

    valid
        .init(Some(json!({ "authorization": "Bearer erin.token.value" })))
        .await;
    invalid
        .init(Some(
            json!({ "authorization": "Bearer nobody.token.value" }),
        ))
        .await;
    missing.init(None).await;

    assert_eq!(valid.next_text().await["type"], "connection_ack");
    assert_eq!(invalid.closed_with().await, 4401);
    assert_eq!(missing.closed_with().await, 4401);
    assert_eq!(harness.seen.connections(), 1);
}

#[tokio::test]
async fn silence_closes_with_4408_and_a_subject_without_the_route_key_with_4403() {
    let harness = Harness::start(Duration::from_millis(300)).await;
    let mut silent = harness.socket(TRANSPORT, None).await;
    let mut denied = harness.socket(TRANSPORT, None).await;

    denied
        .init(Some(json!({ "authorization": "Bearer frank.token.value" })))
        .await;

    assert_eq!(denied.closed_with().await, 4403);
    assert_eq!(silent.closed_with().await, 4408);
    assert_eq!(harness.seen.connections(), 0);
}

#[tokio::test]
async fn the_upstream_gets_the_token_only_when_it_takes_credentials() {
    let harness = Harness::start(BOUND).await;
    let payload = json!({ "authorization": "Bearer erin.token.value", "tenant": "acme" });
    let mut plain = harness.socket(TRANSPORT, None).await;
    plain.init(Some(payload.clone())).await;
    assert_eq!(plain.next_text().await["type"], "connection_ack");
    let mut crediting = harness.connect("/ledger", TRANSPORT, None).await.unwrap();
    crediting.init(Some(payload)).await;
    assert_eq!(crediting.next_text().await["type"], "connection_ack");

    let inits = harness.seen.of_type("connection_init");

    assert_eq!(inits.len(), 2);
    let payloads: Vec<&Value> = inits.iter().map(|init| &init["payload"]).collect();
    assert!(payloads.contains(&&json!({ "tenant": "acme" })));
    assert!(payloads.contains(&&json!({
        "tenant": "acme",
        "authorization": "Bearer erin.token.value",
    })));
}

#[tokio::test]
async fn an_operation_authorized_by_an_expiring_assignment_ends_at_the_expiry() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.acknowledged(TRANSPORT, "gwen").await;
    socket.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;
    wait_for(|| !harness.seen.of_type("subscribe").is_empty()).await;
    assert_eq!(harness.streams.registry().operations(), 1);

    harness.clock.advance(Duration::from_secs(600));

    let error = socket.next_text().await;
    assert_eq!(error["type"], "error");
    assert_eq!(error["id"], "1");
    assert_eq!(error_code(&error), "FORBIDDEN");
    wait_for(|| !harness.seen.of_type("complete").is_empty()).await;
    assert_eq!(harness.seen.of_type("complete")[0]["id"], "1");
}

#[tokio::test]
async fn a_denied_subscription_is_answered_for_its_id_and_never_reaches_the_upstream() {
    let harness = Harness::start(BOUND).await;
    for protocol in [TRANSPORT, LEGACY] {
        let mut socket = harness.acknowledged(protocol, "erin").await;

        socket.operation(protocol, "1", ORDER_DOCUMENT).await;
        socket.operation(protocol, "2", PAYMENT_DOCUMENT).await;

        let error = socket.next_text().await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["id"], "2");
        assert_eq!(error_code(&error), "FORBIDDEN");
        if protocol == TRANSPORT {
            socket.still_open().await;
        }
    }

    wait_for(|| {
        harness.seen.of_type("subscribe").len() == 1 && harness.seen.of_type("start").len() == 1
    })
    .await;
    tokio::time::sleep(QUIET).await;
    let forwarded: Vec<String> = ["subscribe", "start"]
        .iter()
        .flat_map(|kind| harness.seen.of_type(kind))
        .map(|message| message["payload"]["query"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(forwarded, vec![ORDER_DOCUMENT, ORDER_DOCUMENT]);
}

#[tokio::test]
async fn a_mutation_sent_over_the_socket_without_its_key_is_answered_and_not_forwarded() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.acknowledged(TRANSPORT, "erin").await;

    socket
        .operation(TRANSPORT, "5", "mutation { cancel }")
        .await;

    let error = socket.next_text().await;
    assert_eq!(error["id"], "5");
    assert_eq!(error_code(&error), "FORBIDDEN");
    socket.still_open().await;
    assert_eq!(harness.seen.of_type("subscribe"), Vec::<Value>::new());
}

#[tokio::test]
async fn a_message_above_64_kib_and_a_frame_that_does_not_decode_close_with_4400() {
    let harness = Harness::start(BOUND).await;
    let mut large = harness.acknowledged(TRANSPORT, "erin").await;
    let mut garbled = harness.acknowledged(LEGACY, "erin").await;

    large.send_text("x".repeat(70 * 1024)).await;
    garbled.send_text("this is not json".to_owned()).await;

    assert_eq!(large.closed_with().await, 4400);
    assert_eq!(garbled.closed_with().await, 4400);
}

#[tokio::test]
async fn a_revoked_role_completes_the_operation_and_a_revoked_session_closes_the_socket() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.acknowledged(TRANSPORT, "erin").await;
    let mut other = harness.acknowledged(TRANSPORT, "hana").await;
    socket.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;
    other.operation(TRANSPORT, "9", ORDER_DOCUMENT).await;
    wait_for(|| harness.seen.of_type("subscribe").len() == 2).await;
    let without_operation = snapshot_at(8, |subject| {
        if subject.name == "erin" {
            &[ROUTE_KEY, LEDGER_KEY]
        } else {
            subject.grants
        }
    });

    harness
        .apply(
            without_operation,
            &[
                format!("subject/user/{}", user_id(index_of("erin"))),
                format!("subject/user/{}", user_id(index_of("hana"))),
            ],
        )
        .await;

    let error = socket.next_text().await;
    assert_eq!(error["id"], "1");
    assert_eq!(error_code(&error), "FORBIDDEN");
    wait_for(|| harness.seen.of_type("complete").len() == 1).await;
    assert_eq!(harness.seen.of_type("complete")[0]["id"], "1");
    socket.still_open().await;
    other.still_open().await;

    let revoked = snapshot_at(9, |subject| subject.grants)
        .with_revoked_session(SessionId::new("session-erin").unwrap());
    harness
        .apply(revoked, &["revocation/session/session-erin".to_owned()])
        .await;

    assert_eq!(socket.closed_with().await, 4403);
    other.still_open().await;
}

#[tokio::test]
async fn a_payload_with_only_a_persisted_query_or_an_empty_query_is_answered_for_its_id() {
    let harness = Harness::start(BOUND).await;
    for protocol in [TRANSPORT, LEGACY] {
        let kind = if protocol == TRANSPORT {
            "subscribe"
        } else {
            "start"
        };
        let mut socket = harness.acknowledged(protocol, "erin").await;

        socket
            .send(&json!({
                "id": "1",
                "type": kind,
                "payload": { "extensions": { "persistedQuery": { "sha256Hash": "ab" } } },
            }))
            .await;
        socket
            .send(&json!({ "id": "2", "type": kind, "payload": { "query": "" } }))
            .await;

        for id in ["1", "2"] {
            let error = socket.next_text().await;
            assert_eq!(error["type"], "error");
            assert_eq!(error["id"], id);
        }
        if protocol == TRANSPORT {
            socket.still_open().await;
        }
    }

    tokio::time::sleep(QUIET).await;
    assert_eq!(harness.seen.of_type("subscribe"), Vec::<Value>::new());
    assert_eq!(harness.seen.of_type("start"), Vec::<Value>::new());
}

/// A subscription document whose comment tells the fake upstream what to send back.
fn scripted(words: &str) -> String {
    format!("subscription {{ orderUpdated }} # {words}")
}

#[tokio::test]
async fn a_client_that_closes_or_terminates_ends_the_socket_and_its_registration() {
    let harness = Harness::start(BOUND).await;
    let mut closing = harness.acknowledged(TRANSPORT, "erin").await;
    let mut terminating = harness.acknowledged(LEGACY, "hana").await;
    wait_for(|| harness.streams.registry().len() == 2).await;

    closing.frame(Message::Close(None)).await;
    terminating
        .send(&json!({ "type": "connection_terminate" }))
        .await;

    closing.ended().await;
    terminating.ended().await;
    wait_for(|| harness.streams.registry().is_empty()).await;
}

#[tokio::test]
async fn a_client_that_vanishes_leaves_nothing_registered() {
    let harness = Harness::start(BOUND).await;
    let mut open = harness.acknowledged(TRANSPORT, "erin").await;
    open.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;
    wait_for(|| harness.streams.registry().len() == 2).await;

    drop(open);

    wait_for(|| harness.streams.registry().is_empty()).await;
}

#[tokio::test]
async fn what_comes_before_connection_init_is_ignored_or_closes_the_socket() {
    let harness = Harness::start(BOUND).await;
    let mut pinged = harness.socket(TRANSPORT, Some("erin")).await;
    let mut binary = harness.socket(TRANSPORT, Some("erin")).await;
    let mut closing = harness.socket(TRANSPORT, Some("erin")).await;
    let mut early = harness.socket(TRANSPORT, Some("erin")).await;
    let mut garbled = harness.socket(TRANSPORT, None).await;
    let vanishing = harness.socket(TRANSPORT, None).await;

    pinged.frame(Message::Ping(Bytes::new())).await;
    pinged.init(None).await;
    binary
        .frame(Message::Binary(Bytes::from_static(&[1])))
        .await;
    closing.frame(Message::Close(None)).await;
    early.send(&json!({ "type": "ping" })).await;
    garbled.send_text("this is not json".to_owned()).await;
    drop(vanishing);

    assert_eq!(pinged.next_text().await["type"], "connection_ack");
    assert_eq!(binary.closed_with().await, 4400);
    closing.ended().await;
    assert_eq!(early.closed_with().await, 4401);
    assert_eq!(garbled.closed_with().await, 4400);
    assert_eq!(harness.seen.connections(), 1);
}

#[tokio::test]
async fn a_frame_that_is_not_text_or_a_second_init_after_the_ack_is_answered() {
    let harness = Harness::start(BOUND).await;
    let mut binary = harness.acknowledged(TRANSPORT, "erin").await;
    let mut pinged = harness.acknowledged(TRANSPORT, "erin").await;
    let mut again = harness.acknowledged(LEGACY, "erin").await;

    binary
        .frame(Message::Binary(Bytes::from_static(&[1])))
        .await;
    pinged.frame(Message::Ping(Bytes::new())).await;
    again.init(None).await;

    assert_eq!(binary.closed_with().await, 4400);
    pinged.still_open().await;
    assert_eq!(again.closed_with().await, 4429);
}

#[tokio::test]
async fn a_pong_is_relayed_on_the_transport_protocol_only() {
    let harness = Harness::start(BOUND).await;
    let mut transport = harness.acknowledged(TRANSPORT, "erin").await;
    let mut legacy = harness.acknowledged(LEGACY, "erin").await;

    legacy.send(&json!({ "type": "pong" })).await;
    legacy.send(&json!({ "type": "ping" })).await;
    assert_eq!(legacy.next_text().await["type"], "pong");
    transport.send(&json!({ "type": "pong" })).await;

    wait_for(|| harness.seen.of_type("pong").len() == 1).await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(harness.seen.of_type("pong").len(), 1);
}

#[tokio::test]
async fn a_stop_for_an_open_operation_reaches_the_upstream_and_one_for_another_does_not() {
    let harness = Harness::start(BOUND).await;
    for (protocol, stop) in [(TRANSPORT, "complete"), (LEGACY, "stop")] {
        let mut socket = harness.acknowledged(protocol, "erin").await;
        socket.operation(protocol, "1", ORDER_DOCUMENT).await;
        wait_for(|| harness.streams.registry().operations() == 1).await;

        socket.send(&json!({ "id": "7", "type": stop })).await;
        socket.send(&json!({ "id": "1", "type": stop })).await;

        wait_for(|| harness.seen.of_type(stop).len() == 1).await;
        wait_for(|| harness.streams.registry().operations() == 0).await;
        tokio::time::sleep(QUIET).await;
        assert_eq!(harness.seen.of_type(stop).len(), 1);
        assert_eq!(harness.seen.of_type(stop)[0]["id"], "1");
    }
}

#[tokio::test]
async fn an_operation_id_that_is_still_open_closes_the_socket_with_4409() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.acknowledged(TRANSPORT, "erin").await;

    socket.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;
    socket.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;

    assert_eq!(socket.closed_with().await, 4409);
}

#[tokio::test]
async fn the_messages_of_the_upstream_reach_the_client_and_its_complete_ends_the_operation() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.acknowledged(TRANSPORT, "erin").await;

    socket
        .operation(TRANSPORT, "1", &scripted("next binary ping complete"))
        .await;

    let next = socket.next_text().await;
    assert_eq!(next["type"], "next");
    assert_eq!(next["id"], "1");
    assert_eq!(
        socket.next().await,
        Message::Binary(Bytes::from_static(&[1, 2, 3]))
    );
    assert_eq!(socket.next_text().await["type"], "complete");
    wait_for(|| harness.streams.registry().operations() == 0).await;
    socket.still_open().await;
}

#[tokio::test]
async fn an_upstream_that_closes_or_hangs_up_ends_the_socket_with_1013() {
    let harness = Harness::start(BOUND).await;
    let mut closing = harness.acknowledged(TRANSPORT, "erin").await;
    let mut hanging = harness.acknowledged(TRANSPORT, "hana").await;

    closing.operation(TRANSPORT, "1", &scripted("close")).await;
    hanging.operation(TRANSPORT, "1", &scripted("hangup")).await;

    assert_eq!(closing.closed_with().await, 1013);
    assert_eq!(hanging.closed_with().await, 1013);
}

#[tokio::test]
async fn an_upstream_that_does_not_acknowledge_properly_is_unavailable() {
    let harness = Harness::start(Duration::from_millis(500)).await;
    let mut silent = harness.socket(TRANSPORT, Some("erin")).await;
    let mut other = harness.socket(TRANSPORT, Some("erin")).await;
    let mut closing = harness.socket(TRANSPORT, Some("erin")).await;
    let mut pinging = harness.socket(TRANSPORT, Some("erin")).await;

    for (socket, mode) in [
        (&mut silent, "silent"),
        (&mut other, "other"),
        (&mut closing, "close"),
        (&mut pinging, "ping-first"),
    ] {
        socket.init(Some(json!({ "mode": mode }))).await;
    }

    assert_eq!(silent.closed_with().await, 1013);
    assert_eq!(other.closed_with().await, 1013);
    assert_eq!(closing.closed_with().await, 1013);
    assert_eq!(pinging.next_text().await["type"], "connection_ack");
}

#[tokio::test]
async fn an_upstream_that_answers_the_wrong_accept_key_is_unavailable() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness
        .connect_with(
            "/graphql",
            TRANSPORT,
            Some("erin"),
            &[("x-upstream-mode", "bad-accept")],
        )
        .await
        .unwrap();

    socket.init(None).await;

    assert_eq!(socket.closed_with().await, 1013);
}

#[tokio::test]
async fn a_token_the_gateway_cannot_verify_now_closes_the_socket_with_1013() {
    let harness = Harness::start(BOUND).await;
    let mut socket = harness.socket(TRANSPORT, None).await;

    socket
        .init(Some(
            json!({ "authorization": "Bearer unavailable.token.value" }),
        ))
        .await;

    assert_eq!(socket.closed_with().await, 1013);
}

#[tokio::test]
async fn a_full_audit_lane_refuses_the_route_and_the_operation_of_an_audited_key() {
    let harness = Harness::start_with(Options {
        audit_capacity: Some(0),
        ..Options::timeout(BOUND)
    })
    .await;
    let mut route = harness
        .connect("/audited", TRANSPORT, Some("ivy"))
        .await
        .unwrap();
    let mut socket = harness.acknowledged(TRANSPORT, "ivy").await;

    route.init(None).await;
    socket
        .operation(TRANSPORT, "1", "subscription { auditedUpdated }")
        .await;

    assert_eq!(route.closed_with().await, 1013);
    let error = socket.next_text().await;
    assert_eq!(error["id"], "1");
    assert_eq!(error_code(&error), "SERVICE_UNAVAILABLE");
}

#[tokio::test]
async fn an_operation_over_the_parse_budget_is_answered_rate_limited() {
    let harness = Harness::start_with(Options {
        budget: ParseBudgetSettings {
            misses_per_second: 1,
            bytes_per_second: 1 << 20,
        },
        ..Options::timeout(BOUND)
    })
    .await;
    let mut socket = harness.acknowledged(TRANSPORT, "erin").await;

    socket.operation(TRANSPORT, "1", ORDER_DOCUMENT).await;
    socket
        .operation(TRANSPORT, "2", &scripted("a second document"))
        .await;

    let error = socket.next_text().await;
    assert_eq!(error["id"], "2");
    assert_eq!(error_code(&error), "RATE_LIMITED");
}

#[tokio::test]
async fn a_socket_request_that_cannot_be_upgraded_is_answered_400() {
    let harness = Harness::start(BOUND).await;
    let request = Request::get("/graphql")
        .header("host", HOST)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", TRANSPORT)
        .body(Body::empty())
        .unwrap();

    let response = router(harness.pipeline.clone())
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    assert_eq!(harness.seen.connections(), 0);
}
