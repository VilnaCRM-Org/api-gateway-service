//! The frame codec of GraphQL over WebSocket on a route flagged `graphql` and `streaming`
//! (Story 11.3, FR-62).
//!
//! The gateway speaks the two protocols itself on the client side: `graphql-transport-ws` and the
//! legacy `graphql-ws` (the names of the subprotocols; the legacy one is also called
//! `subscriptions-transport-ws`). This module is the part that needs no connection: choosing the
//! subprotocol and answering the upgrade, decoding what a client sends, building what the gateway
//! itself says, and the close codes. The session that drives a socket is
//! `pipeline::socket`, which owns what a decision needs.
//!
//! Frames are decoded in both directions with `tokio-tungstenite`. A client message is inspected
//! and a malformed one is refused; a message of the upstream passes through unchanged, and only
//! its type and operation id are read, so the gateway knows when an operation ended.

use std::time::Duration;

use axum::body::Body;
use axum::http::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use iam_application::GraphQlOperation;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};

use super::pipeline::decode_operation;

/// What the sockets of GraphQL subscriptions are bound by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketSettings {
    /// `GRAPHQL_WS_INIT_TIMEOUT`: how long a client may take to send `connection_init`, and how
    /// long the upstream may take to answer it.
    pub init_timeout: Duration,
}

impl SocketSettings {
    /// The default settings: 5 seconds.
    pub const DEFAULT: Self = Self {
        init_timeout: Duration::from_secs(5),
    };
}

impl Default for SocketSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The longest message of either direction: 64 KiB.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The close code of a message that is not valid for the protocol.
pub const CLOSE_INVALID_MESSAGE: u16 = 4400;

/// The close code of a connection without a valid token.
pub const CLOSE_UNAUTHORIZED: u16 = 4401;

/// The close code of an authenticated caller that may not use the route, and of a revoked
/// session.
pub const CLOSE_FORBIDDEN: u16 = 4403;

/// The close code of a client that sent no `connection_init` in time.
pub const CLOSE_INIT_TIMEOUT: u16 = 4408;

/// The close code of an operation id that is already in use on the connection.
pub const CLOSE_DUPLICATE_ID: u16 = 4409;

/// The close code of a second `connection_init`, and of a subject over its connection limit.
pub const CLOSE_TOO_MANY: u16 = 4429;

/// The close code of a pod or an upstream that cannot serve the socket now.
pub const CLOSE_UNAVAILABLE: u16 = 1013;

/// The `extensions.code` of an operation that the principal may not run.
pub const CODE_FORBIDDEN: &str = "FORBIDDEN";

/// The `extensions.code` of an operation that the envelope rules refuse.
pub const CODE_BAD_REQUEST: &str = "BAD_REQUEST";

/// The `extensions.code` of an operation whose decision could not be made.
pub const CODE_UNAVAILABLE: &str = "SERVICE_UNAVAILABLE";

/// The `extensions.code` of an operation of a subject over its parse budget.
pub const CODE_RATE_LIMITED: &str = "RATE_LIMITED";

/// The subprotocols the gateway speaks, in the order it prefers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `graphql-transport-ws`.
    Transport,
    /// The legacy `graphql-ws`.
    Legacy,
}

impl Protocol {
    /// The name of the subprotocol in `Sec-WebSocket-Protocol`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transport => "graphql-transport-ws",
            Self::Legacy => "graphql-ws",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "graphql-transport-ws" => Some(Self::Transport),
            "graphql-ws" => Some(Self::Legacy),
            _ => None,
        }
    }

    /// The type of the message that starts an operation.
    const fn start(self) -> &'static str {
        match self {
            Self::Transport => "subscribe",
            Self::Legacy => "start",
        }
    }

    /// The type of the message that ends an operation from the client.
    const fn stop(self) -> &'static str {
        match self {
            Self::Transport => "complete",
            Self::Legacy => "stop",
        }
    }
}

/// Why an upgrade request is not answered with `101`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unacceptable {
    /// The client offers no subprotocol the gateway speaks.
    Subprotocol,
    /// The request is not a valid WebSocket handshake.
    Handshake(&'static str),
}

/// What an acceptable upgrade request agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    protocol: Protocol,
    accept: String,
}

impl Handshake {
    /// The subprotocol of the socket.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The `101` answer of the gateway to the client.
    #[must_use]
    pub fn response(&self) -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let headers = response.headers_mut();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(self.protocol.name()),
        );
        if let Ok(accept) = HeaderValue::from_str(&self.accept) {
            headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
        }
        response
    }
}

/// Checks an upgrade request and chooses the subprotocol: the first one in the client's own order
/// that the gateway speaks.
///
/// # Errors
///
/// [`Unacceptable::Subprotocol`] when the client offers none that the gateway speaks, and
/// [`Unacceptable::Handshake`] when the request is not a WebSocket handshake.
pub fn accept(headers: &HeaderMap) -> Result<Handshake, Unacceptable> {
    let protocol = offered(headers)
        .into_iter()
        .find_map(Protocol::parse)
        .ok_or(Unacceptable::Subprotocol)?;
    if !connection_upgrades(headers) {
        return Err(Unacceptable::Handshake(
            "The Connection header must name upgrade.",
        ));
    }
    if headers
        .get(SEC_WEBSOCKET_VERSION)
        .map(HeaderValue::as_bytes)
        != Some(&b"13"[..])
    {
        return Err(Unacceptable::Handshake("The WebSocket version must be 13."));
    }
    let key = headers
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .filter(|key| well_formed_key(key))
        .ok_or(Unacceptable::Handshake(
            "The Sec-WebSocket-Key header is missing or malformed.",
        ))?;
    Ok(Handshake {
        protocol,
        accept: derive_accept_key(key.as_bytes()),
    })
}

/// The subprotocols the client offers, in its order, across every header and comma.
fn offered(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

/// Whether some `Connection` header names the token `upgrade`.
fn connection_upgrades(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// Whether `key` has the shape of 16 bytes in base64.
fn well_formed_key(key: &str) -> bool {
    key.len() == 24
        && key.ends_with("==")
        && key
            .bytes()
            .take(22)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// Whether `headers` ask for a WebSocket upgrade.
#[must_use]
pub fn asks_for_websocket(headers: &HeaderMap) -> bool {
    headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// The longest message of the upstream, whose results are larger than a request: 1 MiB.
pub const MAX_UPSTREAM_MESSAGE_BYTES: usize = 1024 * 1024;

/// The limits of the connection of a client: messages of at most [`MAX_MESSAGE_BYTES`] and small
/// buffers, since a gateway pod holds thousands of sockets.
#[must_use]
pub fn socket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
        .read_buffer_size(8 * 1024)
        .write_buffer_size(0)
}

/// The limits of the connection to an upstream endpoint.
#[must_use]
pub fn upstream_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_UPSTREAM_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_UPSTREAM_MESSAGE_BYTES))
        .read_buffer_size(8 * 1024)
        .write_buffer_size(0)
}

/// A message of the client, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
    /// `connection_init`; `authorization` is the member of its payload that carries a token, and
    /// `payload` is what the upstream is sent, without that member.
    Init {
        /// The `authorization` member of the payload, when it is a string.
        authorization: Option<String>,
        /// The payload without `authorization`; `None` when the message carries none.
        payload: Option<Map<String, Value>>,
    },
    /// `ping`.
    Ping,
    /// `pong`.
    Pong,
    /// `subscribe` or `start`: an operation with the id the client gave it. The operation is the
    /// refusal detail when its payload breaks the envelope rules of Story 10.8.
    Operation {
        /// The id of the operation.
        id: String,
        /// The decoded payload, or why it is refused.
        operation: Result<GraphQlOperation, &'static str>,
    },
    /// `complete` or `stop`: the client ends the operation.
    Stop {
        /// The id of the operation.
        id: String,
    },
    /// `connection_terminate` of the legacy protocol.
    Terminate,
}

/// A frame that is not a valid message of the protocol: the socket is closed with 4400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the frame is not a valid GraphQL over WebSocket message")]
pub struct Malformed;

#[derive(Debug, Deserialize)]
struct Envelope {
    r#type: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    payload: Option<Box<RawValue>>,
}

/// Decodes a text frame of the client.
///
/// # Errors
///
/// [`Malformed`] when the frame is not a JSON object with a known `type` of the protocol, when a
/// member is given twice, when an operation has no id, or when `connection_init` carries a
/// payload that is not an object.
pub fn decode_client(protocol: Protocol, text: &str) -> Result<ClientMessage, Malformed> {
    let envelope: Envelope = serde_json::from_str(text).map_err(|_error| Malformed)?;
    match envelope.r#type.as_str() {
        "connection_init" => init_of(envelope.payload.as_deref()),
        "ping" => Ok(ClientMessage::Ping),
        "pong" => Ok(ClientMessage::Pong),
        "connection_terminate" if protocol == Protocol::Legacy => Ok(ClientMessage::Terminate),
        kind if kind == protocol.start() => {
            let id = identified(envelope.id)?;
            let operation = operation_of(envelope.payload.as_deref());
            Ok(ClientMessage::Operation { id, operation })
        }
        kind if kind == protocol.stop() => Ok(ClientMessage::Stop {
            id: identified(envelope.id)?,
        }),
        _ => Err(Malformed),
    }
}

fn identified(id: Option<String>) -> Result<String, Malformed> {
    id.filter(|id| !id.is_empty()).ok_or(Malformed)
}

/// The payload of `connection_init`: an object or nothing.
fn init_of(payload: Option<&RawValue>) -> Result<ClientMessage, Malformed> {
    let Some(raw) = payload else {
        return Ok(ClientMessage::Init {
            authorization: None,
            payload: None,
        });
    };
    let Ok(Value::Object(mut members)) = serde_json::from_str::<Value>(raw.get()) else {
        return Err(Malformed);
    };
    let authorization = match members.remove("authorization") {
        Some(Value::String(token)) => Some(token),
        _ => None,
    };
    Ok(ClientMessage::Init {
        authorization,
        payload: Some(members),
    })
}

/// The operation of a `subscribe` or `start` payload, under the envelope rules of Story 10.8.
fn operation_of(payload: Option<&RawValue>) -> Result<GraphQlOperation, &'static str> {
    payload.map_or(Err("The payload must be a GraphQL request."), |raw| {
        decode_operation(raw.get())
    })
}

/// What an upstream message means for the operations of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// `connection_ack`.
    Ack,
    /// The operation ended: `complete`, or an `error` for its id.
    Ended(String),
    /// Anything else, which the gateway relays and does not act on.
    Other,
}

/// Reads the type and the id of a text frame of the upstream; a frame that does not decode is
/// `Other` and is relayed unchanged.
#[must_use]
pub fn decode_server(text: &str) -> ServerEvent {
    let Ok(envelope) = serde_json::from_str::<Envelope>(text) else {
        return ServerEvent::Other;
    };
    match (envelope.r#type.as_str(), envelope.id) {
        ("connection_ack", _) => ServerEvent::Ack,
        ("complete" | "error", Some(id)) => ServerEvent::Ended(id),
        _ => ServerEvent::Other,
    }
}

/// The `connection_init` the upstream is sent: the payload the client sent, with `authorization`
/// removed unless `forward_credentials`, in which case the token the connection was
/// authenticated with is put back.
#[must_use]
pub fn upstream_init(
    payload: Option<&Map<String, Value>>,
    credential: Option<&str>,
    forward_credentials: bool,
) -> Message {
    let mut members = payload.cloned().unwrap_or_default();
    if let (true, Some(token)) = (forward_credentials, credential) {
        members.insert("authorization".to_owned(), json!(format!("Bearer {token}")));
    }
    let body = if payload.is_none() && members.is_empty() {
        json!({ "type": "connection_init" })
    } else {
        json!({ "type": "connection_init", "payload": members })
    };
    Message::text(body.to_string())
}

/// The `error` message that answers the operation `id`: a refusal of the gateway, with
/// `extensions.code` set to `code`. The legacy protocol carries one error object, the other a
/// list.
#[must_use]
pub fn error_message(protocol: Protocol, id: &str, code: &str, message: &str) -> Message {
    let error = json!({ "message": message, "extensions": { "code": code } });
    let payload = match protocol {
        Protocol::Transport => json!([error]),
        Protocol::Legacy => error,
    };
    Message::text(json!({ "type": "error", "id": id, "payload": payload }).to_string())
}

/// The `complete` message of the gateway to the upstream, which ends the operation `id` there.
#[must_use]
pub fn complete_message(protocol: Protocol, id: &str) -> Message {
    Message::text(json!({ "type": protocol.stop(), "id": id }).to_string())
}

/// The `pong` that answers a `ping` of the client.
#[must_use]
pub fn pong_message() -> Message {
    Message::text(json!({ "type": "pong" }).to_string())
}

/// The close frame with `code` and a short `reason`.
#[must_use]
pub fn close_frame(code: u16, reason: &str) -> CloseFrame {
    CloseFrame {
        code: CloseCode::from(code),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
