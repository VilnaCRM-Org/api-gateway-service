//! The streams of the forwarder (Story 11.1): the WebSocket upgrade and the SSE response of a
//! request that carries the registration of its stream.

use std::any::Any;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CONNECTION, UPGRADE};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, Version};
use axum::response::Response;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use iam_domain::{ForwardError, UpstreamTarget};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use super::payload::{Payload, ReplayBody};
use super::{
    Answered, ClientKey, HyperUpstreamForwarder, InFlight, Template, classify, endpoint_key,
    relayed, strip_hop_by_hop,
};
use crate::bootstrap::gateway::streams::splice::{self, Upgrades};
use crate::bootstrap::gateway::streams::{StreamHandle, sse};

/// The upgraded connection to an upstream endpoint, handed to the code that speaks WebSocket
/// over it itself (Story 11.3). The permits of the upstream are held until it is dropped.
#[derive(Debug)]
pub struct Tunnel {
    io: TokioIo<Upgraded>,
    _guards: Box<dyn Any + Send>,
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

/// A request extension that asks the forwarder to hand the upgraded upstream connection over.
///
/// The forwarder then does not splice it with the connection of a client. Once the upstream
/// answered `101` the connection arrives on the receiver that [`tunnel`] returned; it never
/// arrives when the upstream refused the upgrade or the upgrade failed.
#[derive(Debug, Clone)]
pub struct TunnelSlot {
    sender: Arc<Mutex<Option<oneshot::Sender<Tunnel>>>>,
}

impl TunnelSlot {
    fn take(&self) -> Option<oneshot::Sender<Tunnel>> {
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// A slot for the request, and the receiver of the upgraded connection.
#[must_use]
pub fn tunnel() -> (TunnelSlot, oneshot::Receiver<Tunnel>) {
    let (sender, receiver) = oneshot::channel();
    let slot = TunnelSlot {
        sender: Arc::new(Mutex::new(Some(sender))),
    };
    (slot, receiver)
}

/// Whether the request asks for a WebSocket over HTTP/1.1 and carries either the registration of
/// its stream, which the pipeline puts there on a route flagged `streaming`, or a slot that takes
/// the upgraded connection over (Story 11.3).
pub(super) fn opens_websocket(request: &Request) -> bool {
    request.version() != Version::HTTP_2
        && (request.extensions().get::<Arc<StreamHandle>>().is_some()
            || request.extensions().get::<TunnelSlot>().is_some())
        && request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// The response of a registered stream: an event stream is kept under the registration of its
/// stream, any other response is the plain response and drops the registration.
pub(super) fn guarded(response: Response, stream: Option<Arc<StreamHandle>>) -> Response {
    match stream {
        Some(handle) if sse::is_event_stream(response.headers()) => sse::guard(response, handle),
        _ => response,
    }
}

/// The upgrade request of `parts`: HTTP/1.1, no hop-by-hop headers but `Upgrade` and
/// `Connection: upgrade`, so the handshake headers of the client reach the endpoint.
fn upgrade_template(parts: Parts) -> Template {
    let mut headers = parts.headers;
    let upgrade = headers.get(UPGRADE).cloned();
    strip_hop_by_hop(&mut headers);
    if let Some(upgrade) = upgrade {
        headers.insert(UPGRADE, upgrade);
    }
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    Template {
        method: parts.method,
        uri: parts.uri,
        version: Version::HTTP_11,
        headers,
    }
}

/// Forwards the WebSocket upgrade of `request` to an endpoint of the upstream of `target`; see
/// [`HyperUpstreamForwarder::forward_upgrade`].
pub(super) async fn forward_upgrade(
    forwarder: &HyperUpstreamForwarder,
    target: UpstreamTarget,
    mut request: Request,
) -> Result<Response, ForwardError> {
    let handle = request.extensions().get::<Arc<StreamHandle>>().cloned();
    let slot = request.extensions().get::<TunnelSlot>().cloned();
    if handle.is_none() && slot.is_none() {
        return Err(ForwardError::NotSent);
    }
    let client = hyper::upgrade::on(&mut request);
    let permit = forwarder.registry.admit(&target)?;
    let endpoint = forwarder.choose(&target, None)?;
    let key = endpoint_key(&endpoint);
    let in_flight = InFlight::enter(&forwarder.in_flight, key.clone());
    let (parts, _body) = request.into_parts();
    let outgoing = upgrade_template(parts).request(&endpoint, Payload::Empty.body())?;
    forwarder.registry.count_request(&target);
    let mut answered = attempt(forwarder, &target, &key, outgoing).await?;
    if answered.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(relayed(answered, None, permit));
    }
    let upstream = hyper::upgrade::on(&mut answered);
    let (parts, _empty) = answered.into_parts();
    let guards = (permit, in_flight);
    match (slot.as_ref().and_then(TunnelSlot::take), handle) {
        (Some(sender), _) => drop(tokio::spawn(hand_over(upstream, sender, guards))),
        (None, Some(handle)) => {
            let upgrades = Upgrades { client, upstream };
            drop(tokio::spawn(splice::run(upgrades, handle, guards)));
        }
        (None, None) => {}
    }
    Ok(Response::from_parts(parts, Body::empty()))
}

/// Waits for the upstream connection to upgrade and hands it, with `guards`, to the receiver of
/// the tunnel.
async fn hand_over<G: Send + 'static>(
    upstream: hyper::upgrade::OnUpgrade,
    sender: oneshot::Sender<Tunnel>,
    guards: G,
) {
    if let Ok(upgraded) = upstream.await {
        drop(sender.send(Tunnel {
            io: TokioIo::new(upgraded),
            _guards: Box::new(guards),
        }));
    }
}

/// The one attempt of an upgrade: the answer must arrive within the response timeout, over a
/// pooled HTTP/1.1 client, whatever protocol the upstream speaks for its requests, because the
/// WebSocket handshake needs it.
async fn attempt(
    forwarder: &HyperUpstreamForwarder,
    target: &UpstreamTarget,
    key: &str,
    outgoing: axum::http::Request<ReplayBody>,
) -> Result<Answered, ForwardError> {
    let client = forwarder.pooled(ClientKey {
        http2: false,
        connect_ms: target.connect_timeout_ms(),
    });
    let wait = Duration::from_millis(u64::from(target.headers_timeout_ms()));
    match tokio::time::timeout(wait, client.request(outgoing)).await {
        Ok(Ok(answered)) => {
            forwarder.settle(target, key, answered.status().is_server_error());
            Ok(answered)
        }
        Ok(Err(error)) => Err(forwarder.failed(target, key, classify(&error)).error),
        Err(_elapsed) => Err(ForwardError::ResponseTimeout),
    }
}

#[cfg(test)]
mod tests;
