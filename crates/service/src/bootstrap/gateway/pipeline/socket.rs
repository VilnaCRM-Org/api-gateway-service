//! The GraphQL subscription sockets of the pipeline (Story 11.3, FR-62).
//!
//! A `GET` upgrade on a route flagged `graphql` and `streaming` is not spliced like the streams
//! of Story 11.1: the gateway completes the handshake with the client itself, chooses the
//! subprotocol (`graphql-transport-ws` or `graphql-ws`; any other is 400 before the upgrade) and
//! speaks the protocol on the client side, so no upstream connection exists for a client that
//! has not authenticated.
//!
//! The socket then goes through these steps, each one closing it with its own code:
//!
//! 1. `connection_init` within `GRAPHQL_WS_INIT_TIMEOUT` (silence: 4408);
//! 2. the token of the upgrade request, or else the `authorization` member of the payload,
//!    verified on the published snapshot (missing or invalid: 4401);
//! 3. the route decision on the authenticated principal (denied: 4403);
//! 4. only now the upstream WebSocket, the `connection_init` without `authorization` (unless the
//!    upstream has `forwardCredentials = true`), the relay of its `connection_ack` and the
//!    registration of the connection in the stream registry.
//!
//! After that every `subscribe` or `start` message, and every query or mutation sent over the
//! socket, is authorized before it is forwarded and registered as an operation of the registry;
//! a denial answers its id with an `error` carrying `extensions.code = FORBIDDEN` and the socket
//! stays open. The registry decides an operation again like a stream (Story 11.2): when it is
//! denied the gateway sends `complete` upstream and `error` downstream, and a revoked session
//! closes the socket with 4403.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{
    SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::Response;
use futures_util::future::OptionFuture;
use futures_util::{Sink, SinkExt as _, StreamExt as _};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use iam_application::{
    Authorization, GraphQlOperation, OperationVerdict, Principal, RouteRequest,
    SubscriptionAuthorizer,
};
use iam_domain::{
    Credential, ForwardError, HttpMethod, NormalizedPath, PathNormalizer, PolicySnapshot,
    RouteState, UpstreamTarget,
};
use iam_infrastructure::SnapshotRevocationView;
use serde_json::{Map, Value};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::{Error as WsError, Message, Utf8Bytes};

use super::headers::{self, Propagated};
use super::rate_limit::ClientAddress;
use super::stream::earliest_expiry;
use super::{
    Admitted, Pipeline, Refusal, connection_limit, cors, forwarded_uri, host_of, principal_of,
    request_id_of, route_for_host, target_of,
};
use crate::bootstrap::gateway::graphql_ws::{
    self, CLOSE_DUPLICATE_ID, CLOSE_FORBIDDEN, CLOSE_INIT_TIMEOUT, CLOSE_INVALID_MESSAGE,
    CLOSE_TOO_MANY, CLOSE_UNAUTHORIZED, CLOSE_UNAVAILABLE, CODE_BAD_REQUEST, CODE_FORBIDDEN,
    CODE_RATE_LIMITED, CODE_UNAVAILABLE, ClientMessage, Handshake, Protocol, ServerEvent,
    Unacceptable,
};
use crate::bootstrap::gateway::streams::{CloseReason, Grant, StreamHandle, StreamRecord, Streams};
use crate::bootstrap::gateway::upstream::{Tunnel, TunnelSlot, tunnel};
use crate::http::authentication::credential as request_credential;

/// How long the close frame may take to reach a client that does not read.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

type Client = WebSocketStream<TokioIo<Upgraded>>;
type Upstream = WebSocketStream<Tunnel>;
type Ended = mpsc::UnboundedSender<(String, CloseReason)>;

/// Whether the request opens a GraphQL socket: a `GET` that asks for a WebSocket on a route
/// flagged `graphql` and `streaming`, on a pipeline that has a stream registry.
pub(super) fn opens(
    pipeline: &Pipeline,
    snapshot: &Arc<dyn PolicySnapshot>,
    parts: &Parts,
    method: HttpMethod,
    path: &NormalizedPath,
) -> bool {
    pipeline.streams.is_some()
        && method == HttpMethod::Get
        && graphql_ws::asks_for_websocket(&parts.headers)
        && super::route_of(snapshot, parts, method, path).is_some_and(|route| {
            let flags = route.fields.flags();
            flags.graphql() && flags.streaming()
        })
}

/// Admits the upgrade request: the subprotocol is chosen and the handshake checked before
/// anything else, and the cross-site rule of the route applies to a cookie that rides on the
/// upgrade. Nothing is authenticated here: that waits for `connection_init`.
pub(super) fn admit(
    snapshot: &Arc<dyn PolicySnapshot>,
    parts: &Parts,
    route: &RouteState,
    path: &NormalizedPath,
) -> Result<Admitted, Refusal> {
    let handshake = graphql_ws::accept(&parts.headers).map_err(refused)?;
    cors::csrf(parts, HttpMethod::Get, route)?;
    let upstream = snapshot
        .upstream_by_id(route.fields.upstream_id())
        .ok_or(Refusal::Failed(ForwardError::NoEndpoint))?;
    Ok(Admitted {
        target: target_of(upstream, route),
        uri: forwarded_uri(path, None).ok_or(Refusal::MalformedPath)?,
        principal: None,
        version: snapshot.version().value(),
        body: Body::empty(),
        stream: None,
        socket: Some(handshake),
    })
}

const fn refused(unacceptable: Unacceptable) -> Refusal {
    match unacceptable {
        Unacceptable::Subprotocol => Refusal::BadRequest(
            "The WebSocket subprotocol must be graphql-transport-ws or graphql-ws.",
        ),
        Unacceptable::Handshake(detail) => Refusal::BadRequest(detail),
    }
}

/// Answers the upgrade `101` and runs the socket on a task of its own once the client's
/// connection is upgraded. A request that cannot be upgraded (HTTP/2) is answered 400.
pub(super) fn open(pipeline: &Pipeline, mut parts: Parts, handshake: &Handshake) -> Response {
    let Some(upgrade) = parts.extensions.remove::<OnUpgrade>() else {
        return super::graphql::bad_request("A GraphQL socket needs an HTTP/1.1 upgrade.");
    };
    let session = Session {
        pipeline: pipeline.clone(),
        host: host_of(&parts).unwrap_or_default(),
        parts,
        protocol: handshake.protocol(),
        subscriptions: SubscriptionAuthorizer::new(Arc::clone(&pipeline.authorizer)),
    };
    drop(tokio::spawn(session.run(upgrade)));
    handshake.response()
}

/// The published snapshot, while the pod is proven fresh.
fn fresh_snapshot(pipeline: &Pipeline) -> Option<Arc<dyn PolicySnapshot>> {
    let snapshot = pipeline.view.current()?;
    pipeline.freshness.is_fresh().then_some(snapshot)
}

/// The principal a credential proves on `snapshot`: its token is verified, checked against the
/// revocation sets of the snapshot and, on the east-west listener, against the caller rule.
async fn resolve_credential(
    pipeline: &Pipeline,
    snapshot: &Arc<dyn PolicySnapshot>,
    credential: &Credential,
) -> Result<Principal, Refusal> {
    let revocations = SnapshotRevocationView::over(Arc::clone(snapshot));
    let resolved = pipeline
        .tokens
        .resolve_with(&revocations, credential)
        .await
        .and_then(|identity| pipeline.check_caller(identity));
    principal_of(resolved)
}

/// Why a socket ends, and what the client is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The gateway closes the socket with this code and reason.
    Close(u16, &'static str),
    /// The client is gone: there is nobody to tell.
    Gone,
}

const UNAVAILABLE: Ending = Ending::Close(CLOSE_UNAVAILABLE, "try again later");

/// What a message of the client does to the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    End,
}

/// What `connection_init` carried: the token of its payload and the payload the upstream is sent.
#[derive(Debug)]
struct Init {
    authorization: Option<String>,
    payload: Option<Map<String, Value>>,
}

/// What the connection knows once its client is authenticated and allowed.
#[derive(Debug)]
struct Admission {
    principal: Principal,
    /// The token the connection was authenticated with, for an upstream that takes credentials.
    token: String,
    target: UpstreamTarget,
    forward_credentials: bool,
    version: i64,
    record: StreamRecord,
    grant: Grant,
}

/// What an operation is answered when it is not run: the code and the message of its `error`.
type Refused = (&'static str, &'static str);

const CANNOT_DECIDE: Refused = (CODE_UNAVAILABLE, "The operation cannot be decided now.");
const NOT_PERMITTED: Refused = (CODE_FORBIDDEN, "The operation is not permitted.");

/// What the registry holds about an operation that was allowed, and what decides it again.
type Registration = Box<(StreamRecord, Grant)>;

/// One socket.
#[derive(Debug)]
struct Session {
    pipeline: Pipeline,
    parts: Parts,
    host: String,
    protocol: Protocol,
    subscriptions: SubscriptionAuthorizer,
}

impl Session {
    /// Serves the socket once the connection of the client is upgraded; a connection that never
    /// is has nothing to serve.
    async fn run(self, upgrade: OnUpgrade) {
        let serving = upgrade.await.ok().map(|upgraded| self.serve(upgraded));
        OptionFuture::from(serving).await.unwrap_or_default();
    }

    async fn serve(&self, upgraded: Upgraded) {
        let mut client = WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            Role::Server,
            Some(graphql_ws::socket_config()),
        )
        .await;
        match self.drive(&mut client).await {
            Ok(()) => goodbye(&mut client, None).await,
            Err(Ending::Close(code, reason)) => {
                goodbye(&mut client, Some(graphql_ws::close_frame(code, reason))).await;
            }
            Err(Ending::Gone) => {}
        }
    }

    async fn drive(&self, client: &mut Client) -> Result<(), Ending> {
        let init = self.await_init(client).await?;
        let admission = self.admit(init.authorization.as_deref()).await?;
        let mut upstream = self.connect(&admission, init.payload.as_ref()).await?;
        let ack = self.acknowledge(&mut upstream).await?;
        let streams = self.pipeline.streams.as_ref().ok_or(UNAVAILABLE)?;
        let connection = streams
            .registry()
            .open(admission.record.clone(), admission.grant.clone())
            .map_err(|_capped| Ending::Close(CLOSE_TOO_MANY, "too many streams"))?;
        send(client, ack).await?;
        streams.admit(connection.id()).await;
        let (ended, events) = mpsc::unbounded_channel();
        Serving {
            session: self,
            streams,
            admission,
            connection,
            operations: HashMap::new(),
            ended,
        }
        .run(client, &mut upstream, events)
        .await
    }

    /// Reads `connection_init` within the timeout.
    async fn await_init(&self, client: &mut Client) -> Result<Init, Ending> {
        tokio::time::timeout(self.pipeline.sockets.init_timeout, self.read_init(client))
            .await
            .map_err(|_elapsed| Ending::Close(CLOSE_INIT_TIMEOUT, "initialisation timeout"))?
    }

    async fn read_init(&self, client: &mut Client) -> Result<Init, Ending> {
        loop {
            let message = client.next().await.unwrap_or(Ok(Message::Close(None)));
            match message {
                Err(error) => return Err(read_failure(&error)),
                Ok(Message::Text(text)) => return self.first(text.as_str()),
                Ok(Message::Binary(_)) => {
                    return Err(Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message"));
                }
                Ok(Message::Close(_)) => return Err(Ending::Gone),
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            }
        }
    }

    /// The first message of a connection must be `connection_init`.
    fn first(&self, text: &str) -> Result<Init, Ending> {
        match graphql_ws::decode_client(self.protocol, text) {
            Ok(ClientMessage::Init {
                authorization,
                payload,
            }) => Ok(Init {
                authorization,
                payload,
            }),
            Ok(_other) => Err(Ending::Close(CLOSE_UNAUTHORIZED, "unauthorized")),
            Err(_malformed) => Err(Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message")),
        }
    }

    /// Authenticates the connection and decides its route; the snapshot is dropped before the
    /// upstream is reached.
    async fn admit(&self, init_authorization: Option<&str>) -> Result<Admission, Ending> {
        let credential = SubscriptionAuthorizer::connection_credential(
            request_credential(&self.parts.headers),
            init_authorization,
        );
        if credential.is_blank() {
            return Err(Ending::Close(CLOSE_UNAUTHORIZED, "unauthorized"));
        }
        let snapshot = fresh_snapshot(&self.pipeline).ok_or(UNAVAILABLE)?;
        let principal = self.authenticate(&snapshot, &credential).await?;
        let path = self.path()?;
        let route = route_for_host(&snapshot, &self.host, HttpMethod::Get, &path)
            .ok_or(Ending::Close(CLOSE_FORBIDDEN, "forbidden"))?;
        let request = self.request(&snapshot, route, &path);
        let traced = self
            .subscriptions
            .authorize_route(&request, &principal)
            .await;
        match traced.authorization {
            Authorization::Allowed(_) | Authorization::WouldDeny(_) => {}
            Authorization::Denied(_) => return Err(Ending::Close(CLOSE_FORBIDDEN, "forbidden")),
            Authorization::Unavailable | Authorization::AuditUnavailable => {
                return Err(UNAVAILABLE);
            }
        }
        let upstream = snapshot
            .upstream_by_id(route.fields.upstream_id())
            .ok_or(UNAVAILABLE)?;
        let streams = self.pipeline.streams.as_ref().ok_or(UNAVAILABLE)?;
        let record = StreamRecord {
            required_keys: traced.trace.permission_key.into_iter().collect(),
            ..record_of(&principal, &snapshot, route, streams)
        };
        Ok(Admission {
            token: credential.expose().to_owned(),
            target: target_of(upstream, route),
            forward_credentials: upstream.settings.forward_credentials(),
            version: snapshot.version().value(),
            grant: self.grant(&principal, None),
            record,
            principal,
        })
    }

    /// The principal the credential proves, holding a connection slot of its subject.
    async fn authenticate(
        &self,
        snapshot: &Arc<dyn PolicySnapshot>,
        credential: &Credential,
    ) -> Result<Principal, Ending> {
        let principal = match resolve_credential(&self.pipeline, snapshot, credential).await {
            Ok(principal) => principal,
            Err(Refusal::Stale) => return Err(UNAVAILABLE),
            Err(_refused) => return Err(Ending::Close(CLOSE_UNAUTHORIZED, "unauthorized")),
        };
        connection_limit::claim(&self.parts, &principal)
            .map_err(|_limit| Ending::Close(CLOSE_TOO_MANY, "too many connections"))?;
        Ok(principal)
    }

    fn path(&self) -> Result<NormalizedPath, Ending> {
        PathNormalizer::normalize(self.parts.uri.path())
            .map_err(|_rule| Ending::Close(CLOSE_FORBIDDEN, "forbidden"))
    }

    fn request<'request>(
        &'request self,
        snapshot: &'request Arc<dyn PolicySnapshot>,
        route: &'request RouteState,
        path: &'request NormalizedPath,
    ) -> RouteRequest<'request> {
        RouteRequest {
            snapshot,
            service: route.fields.service(),
            enforcement: route.fields.enforcement(),
            method: HttpMethod::Get,
            path,
            request_id: request_id_of(&self.parts.headers),
        }
    }

    fn grant(&self, principal: &Principal, operation: Option<Arc<GraphQlOperation>>) -> Grant {
        Grant {
            principal: Some(principal.clone()),
            host: self.host.clone(),
            method: HttpMethod::Get,
            path: self.parts.uri.path().to_owned(),
            operation,
        }
    }

    /// Opens the upstream WebSocket and sends it the `connection_init`.
    async fn connect(
        &self,
        admission: &Admission,
        payload: Option<&Map<String, Value>>,
    ) -> Result<Upstream, Ending> {
        let (slot, tunnel) = tunnel();
        let request = self.upstream_request(admission, slot)?;
        let answered = self
            .pipeline
            .forwarder
            .forward(admission.target.clone(), request)
            .await
            .map_err(|_failed| UNAVAILABLE)?;
        self.verify(&answered)?;
        let tunnel = tunnel.await.map_err(|_refused| UNAVAILABLE)?;
        let mut upstream = WebSocketStream::from_raw_socket(
            tunnel,
            Role::Client,
            Some(graphql_ws::upstream_config()),
        )
        .await;
        let init = graphql_ws::upstream_init(
            payload,
            Some(admission.token.as_str()),
            admission.forward_credentials,
        );
        push(&mut upstream, init).await?;
        Ok(upstream)
    }

    /// The upgrade request to the upstream: the headers of the client's handshake, rewritten like
    /// those of any admitted request, and the subprotocol the gateway chose. Extensions are not
    /// offered, since the gateway reads every frame.
    fn upstream_request(&self, admission: &Admission, slot: TunnelSlot) -> Result<Request, Ending> {
        let path = self.path()?;
        let uri = forwarded_uri(&path, None).ok_or(UNAVAILABLE)?;
        let (mut parts, ()) = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(())
            .map_err(|_invalid| UNAVAILABLE)?
            .into_parts();
        parts.headers.clone_from(&self.parts.headers);
        if let Some(client) = self.parts.extensions.get::<ClientAddress>().copied() {
            parts.extensions.insert(client);
        }
        headers::rewrite(
            &mut parts,
            &Propagated {
                principal: &admission.principal,
                version: admission.version,
                forward_credentials: admission.forward_credentials,
            },
        );
        parts.headers.remove(SEC_WEBSOCKET_EXTENSIONS);
        parts.headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(self.protocol.name()),
        );
        let mut request = Request::from_parts(parts, Body::empty());
        request.extensions_mut().insert(slot);
        Ok(request)
    }

    /// The upstream must switch protocols, prove it read this handshake and speak the subprotocol
    /// that was chosen.
    fn verify(&self, answered: &Response) -> Result<(), Ending> {
        let key = self
            .parts
            .headers
            .get(SEC_WEBSOCKET_KEY)
            .map(HeaderValue::as_bytes)
            .ok_or(UNAVAILABLE)?;
        let expected = derive_accept_key(key);
        let accepted = answered
            .headers()
            .get(SEC_WEBSOCKET_ACCEPT)
            .and_then(|value| value.to_str().ok())
            == Some(expected.as_str());
        let protocol = answered
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            == Some(self.protocol.name());
        if answered.status() == StatusCode::SWITCHING_PROTOCOLS && accepted && protocol {
            Ok(())
        } else {
            Err(UNAVAILABLE)
        }
    }

    /// Waits for the `connection_ack` of the upstream, which is relayed unchanged.
    async fn acknowledge(&self, upstream: &mut Upstream) -> Result<Message, Ending> {
        let wait = async {
            loop {
                match upstream.next().await {
                    Some(Ok(Message::Text(text))) => {
                        return match graphql_ws::decode_server(text.as_str()) {
                            ServerEvent::Ack => Ok(Message::Text(text)),
                            ServerEvent::Ended(_) | ServerEvent::Other => Err(UNAVAILABLE),
                        };
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    _ => return Err(UNAVAILABLE),
                }
            }
        };
        tokio::time::timeout(self.pipeline.sockets.init_timeout, wait)
            .await
            .map_err(|_elapsed| UNAVAILABLE)?
    }

    /// Decides an operation on the published snapshot: what a request for it would be answered,
    /// and what the registry needs to decide it again.
    async fn decide(
        &self,
        admission: &Admission,
        operation: GraphQlOperation,
    ) -> Result<Registration, Refused> {
        let streams = self.pipeline.streams.as_ref().ok_or(CANNOT_DECIDE)?;
        let snapshot = fresh_snapshot(&self.pipeline).ok_or(CANNOT_DECIDE)?;
        let path = self.path().map_err(|_ending| NOT_PERMITTED)?;
        let route =
            route_for_host(&snapshot, &self.host, HttpMethod::Get, &path).ok_or(NOT_PERMITTED)?;
        let request = self.request(&snapshot, route, &path);
        let principal = &admission.principal;
        let verdict = self
            .subscriptions
            .authorize_operation(&request, principal, &operation)
            .await;
        match verdict {
            OperationVerdict::Allowed { keys, .. } => {
                let record = StreamRecord {
                    required_keys: keys,
                    ..record_of(principal, &snapshot, route, streams)
                };
                let grant = self.grant(principal, Some(Arc::new(operation)));
                Ok(Box::new((record, grant)))
            }
            OperationVerdict::Forbidden(_reason) => Err(NOT_PERMITTED),
            OperationVerdict::RateLimited => {
                Err((CODE_RATE_LIMITED, "Too many operations were parsed."))
            }
            OperationVerdict::Unavailable => Err(CANNOT_DECIDE),
        }
    }
}

/// What the registry holds about the connection or an operation of `principal` on `route`.
fn record_of(
    principal: &Principal,
    snapshot: &Arc<dyn PolicySnapshot>,
    route: &RouteState,
    streams: &Streams,
) -> StreamRecord {
    StreamRecord {
        subject: Some(principal.subject().to_string()),
        session: principal
            .session()
            .map(|session| session.as_str().to_owned()),
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: Some(principal.expires_at()),
        assignment_expires_at: earliest_expiry(snapshot, principal, streams.now()),
        version: snapshot.version().value(),
        route: Some(route.id),
        service: Some(route.fields.service().clone()),
    }
}

/// An operation that is open on the socket: its registration, and the task that tells the socket
/// when the registry ends it.
#[derive(Debug)]
struct OpenOperation {
    _handle: StreamHandle,
    watcher: AbortHandle,
}

impl Drop for OpenOperation {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

fn watch(id: &str, handle: StreamHandle, ended: &Ended) -> OpenOperation {
    let closed = handle.closed();
    let id = id.to_owned();
    let ended = ended.clone();
    let task = tokio::spawn(async move {
        let reason = closed.await;
        drop(ended.send((id, reason)));
    });
    OpenOperation {
        _handle: handle,
        watcher: task.abort_handle(),
    }
}

/// What happened to the socket.
enum Event {
    /// The registry closed the connection.
    Closed(CloseReason),
    /// The registry ended an operation.
    Operation(String),
    /// The client sent a frame, or its side ended.
    Client(Option<Result<Message, WsError>>),
    /// The upstream sent a frame, or its side ended.
    Upstream(Option<Result<Message, WsError>>),
}

/// Waits for the first thing that happens to the connection.
async fn next_event(
    connection: &StreamHandle,
    client: &mut Client,
    upstream: &mut Upstream,
    events: &mut mpsc::UnboundedReceiver<(String, CloseReason)>,
) -> Event {
    tokio::select! {
        reason = connection.closed() => Event::Closed(reason),
        Some((id, _reason)) = events.recv() => Event::Operation(id),
        message = client.next() => Event::Client(message),
        message = upstream.next() => Event::Upstream(message),
    }
}

/// The socket after its connection was registered.
struct Serving<'session> {
    session: &'session Session,
    streams: &'session Arc<Streams>,
    admission: Admission,
    connection: StreamHandle,
    operations: HashMap<String, OpenOperation>,
    ended: Ended,
}

impl Serving<'_> {
    async fn run(
        mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        mut events: mpsc::UnboundedReceiver<(String, CloseReason)>,
    ) -> Result<(), Ending> {
        loop {
            if self.step(client, upstream, &mut events).await? == Flow::End {
                return Ok(());
            }
        }
    }

    /// Waits for the next thing that happens to the socket and handles it.
    async fn step(
        &mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        events: &mut mpsc::UnboundedReceiver<(String, CloseReason)>,
    ) -> Result<Flow, Ending> {
        match next_event(&self.connection, client, upstream, events).await {
            Event::Closed(reason) => {
                Err(Ending::Close(close_code(reason), "closed by the gateway"))
            }
            Event::Operation(id) => {
                self.finished(client, upstream, &id).await?;
                Ok(Flow::Continue)
            }
            Event::Client(message) => self.client_message(client, upstream, message).await,
            Event::Upstream(message) => {
                self.upstream_message(client, message).await?;
                Ok(Flow::Continue)
            }
        }
    }

    /// The registry ended the operation `id`: the upstream is told to complete it and the client
    /// gets the `error`.
    async fn finished(
        &mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        id: &str,
    ) -> Result<(), Ending> {
        let ended = self
            .operations
            .remove(id)
            .map(|_open| self.end_operation(client, upstream, id));
        OptionFuture::from(ended).await.unwrap_or(Ok(()))
    }

    async fn end_operation(
        &self,
        client: &mut Client,
        upstream: &mut Upstream,
        id: &str,
    ) -> Result<(), Ending> {
        let protocol = self.session.protocol;
        push(upstream, graphql_ws::complete_message(protocol, id)).await?;
        let error = graphql_ws::error_message(
            protocol,
            id,
            CODE_FORBIDDEN,
            "The operation is no longer permitted.",
        );
        send(client, error).await
    }

    async fn client_message(
        &mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        message: Option<Result<Message, WsError>>,
    ) -> Result<Flow, Ending> {
        let message = match message.unwrap_or(Ok(Message::Close(None))) {
            Ok(message) => message,
            Err(error) => return Err(read_failure(&error)),
        };
        self.connection.activity().touch();
        match message {
            Message::Text(text) => self.text(client, upstream, text).await,
            Message::Binary(_) => Err(Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message")),
            Message::Close(_) => Ok(Flow::End),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(Flow::Continue),
        }
    }

    async fn text(
        &mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        text: Utf8Bytes,
    ) -> Result<Flow, Ending> {
        let protocol = self.session.protocol;
        let decoded = graphql_ws::decode_client(protocol, text.as_str())
            .map_err(|_malformed| Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message"))?;
        match decoded {
            ClientMessage::Init { .. } => Err(Ending::Close(
                CLOSE_TOO_MANY,
                "too many initialisation requests",
            )),
            ClientMessage::Ping => {
                send(client, graphql_ws::pong_message()).await?;
                Ok(Flow::Continue)
            }
            ClientMessage::Pong => {
                if protocol == Protocol::Transport {
                    push(upstream, Message::Text(text)).await?;
                }
                Ok(Flow::Continue)
            }
            ClientMessage::Terminate => Ok(Flow::End),
            ClientMessage::Stop { id } => {
                if self.operations.remove(&id).is_some() {
                    push(upstream, Message::Text(text)).await?;
                }
                Ok(Flow::Continue)
            }
            ClientMessage::Operation { id, operation } => {
                self.start(client, upstream, (id, operation), text).await?;
                Ok(Flow::Continue)
            }
        }
    }

    /// A `subscribe` or `start`: the operation is decided, registered and only then forwarded.
    async fn start(
        &mut self,
        client: &mut Client,
        upstream: &mut Upstream,
        (id, operation): (String, Result<GraphQlOperation, &'static str>),
        text: Utf8Bytes,
    ) -> Result<(), Ending> {
        let protocol = self.session.protocol;
        if self.operations.contains_key(&id) {
            return Err(Ending::Close(
                CLOSE_DUPLICATE_ID,
                "subscriber already exists",
            ));
        }
        let operation = match operation {
            Ok(operation) => operation,
            Err(detail) => {
                let error = graphql_ws::error_message(protocol, &id, CODE_BAD_REQUEST, detail);
                return send(client, error).await;
            }
        };
        match self.session.decide(&self.admission, operation).await {
            Ok(registration) => {
                let (record, grant) = *registration;
                let handle = self.streams.registry().open_operation(record, grant);
                self.streams.admit(handle.id()).await;
                let open = watch(&id, handle, &self.ended);
                self.operations.insert(id, open);
                push(upstream, Message::Text(text)).await
            }
            Err((code, message)) => {
                send(
                    client,
                    graphql_ws::error_message(protocol, &id, code, message),
                )
                .await
            }
        }
    }

    /// A message of the upstream passes through unchanged; its type is read only to know when an
    /// operation ended, and the socket ends with the upstream.
    async fn upstream_message(
        &mut self,
        client: &mut Client,
        message: Option<Result<Message, WsError>>,
    ) -> Result<(), Ending> {
        let message = message.and_then(Result::ok).unwrap_or(Message::Close(None));
        self.connection.activity().touch();
        match message {
            Message::Text(text) => {
                if let ServerEvent::Ended(id) = graphql_ws::decode_server(text.as_str()) {
                    self.operations.remove(&id);
                }
                send(client, Message::Text(text)).await
            }
            Message::Binary(bytes) => send(client, Message::Binary(bytes)).await,
            Message::Close(_) => Err(Ending::Close(CLOSE_UNAVAILABLE, "upstream ended")),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(()),
        }
    }
}

/// The close code of a connection the registry closed: a revoked session or a policy that no
/// longer allows the route is 4403, any other reason keeps its code.
const fn close_code(reason: CloseReason) -> u16 {
    match reason {
        CloseReason::Revoked => CLOSE_FORBIDDEN,
        CloseReason::TokenExpired | CloseReason::Fenced | CloseReason::Idle => reason.code(),
    }
}

/// How a failed read ends the socket: a closed or broken connection leaves nobody to tell, any
/// other failure is a frame that does not decode or is too large.
const fn read_failure(error: &WsError) -> Ending {
    match error {
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Io(_) => Ending::Gone,
        WsError::Tls(_)
        | WsError::Capacity(_)
        | WsError::Protocol(_)
        | WsError::WriteBufferFull(_)
        | WsError::Utf8(_)
        | WsError::AttackAttempt
        | WsError::Url(_)
        | WsError::Http(_)
        | WsError::HttpFormat(_) => Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message"),
    }
}

/// Closes the socket of the client within [`CLOSE_GRACE`]: the close frame goes out, and what the
/// client still sends is read away until it ends, so that closing the connection with unread
/// bytes does not reset it before the client has read the frame.
async fn goodbye(client: &mut Client, frame: Option<CloseFrame>) {
    let closing = async {
        drop(client.close(frame).await);
        let mut sink = [0_u8; 1024];
        while matches!(client.get_mut().read(&mut sink).await, Ok(read) if read > 0) {}
    };
    drop(tokio::time::timeout(CLOSE_GRACE, closing).await);
}

/// Sends a message to the upstream; an upstream that cannot take it is unavailable, and the client
/// is told so.
async fn push(upstream: &mut Upstream, message: Message) -> Result<(), Ending> {
    upstream.send(message).await.map_err(|_failed| UNAVAILABLE)
}

/// Sends a message to the client; a socket that cannot take it is gone.
async fn send<S>(socket: &mut S, message: Message) -> Result<(), Ending>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    socket.send(message).await.map_err(|_failed| Ending::Gone)
}

#[cfg(test)]
mod tests;
