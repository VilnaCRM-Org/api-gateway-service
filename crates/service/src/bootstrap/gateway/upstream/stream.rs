//! The streams of the forwarder (Story 11.1): the WebSocket upgrade and the SSE response of a
//! request that carries the registration of its stream.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CONNECTION, UPGRADE};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, Version};
use axum::response::Response;
use iam_domain::{ForwardError, UpstreamTarget};

use super::payload::{Payload, ReplayBody};
use super::{
    Answered, ClientKey, HyperUpstreamForwarder, InFlight, Template, classify, endpoint_key,
    relayed, strip_hop_by_hop,
};
use crate::bootstrap::gateway::streams::splice::{self, Upgrades};
use crate::bootstrap::gateway::streams::{StreamHandle, sse};

/// Whether the request asks for a WebSocket over HTTP/1.1 and carries the registration of its
/// stream, which the pipeline puts there on a route flagged `streaming`.
pub(super) fn opens_websocket(request: &Request) -> bool {
    request.version() != Version::HTTP_2
        && request.extensions().get::<Arc<StreamHandle>>().is_some()
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
    let Some(handle) = request.extensions().get::<Arc<StreamHandle>>().cloned() else {
        return Err(ForwardError::NotSent);
    };
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
    let upgrades = Upgrades { client, upstream };
    drop(tokio::spawn(splice::run(
        upgrades,
        handle,
        (permit, in_flight),
    )));
    Ok(Response::from_parts(parts, Body::empty()))
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
