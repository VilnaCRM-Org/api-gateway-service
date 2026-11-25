//! SSE responses through the gateway (Story 11.1).
//!
//! The response of an event stream is relayed as it arrives: the gateway adds no compression and no
//! response timeout (a streaming route has none), and the body is only wrapped so that the stream
//! stays registered while it flows, counts its frames as traffic and ends when the registry closes
//! it.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use hyper::body::{Body as HttpBody, Frame, SizeHint};

use super::registry::{CloseReason, StreamHandle};

/// Whether `headers` describe a `text/event-stream` response.
#[must_use]
pub fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .get(.."text/event-stream".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/event-stream"))
        })
}

/// The response with its body under the registration of the stream of `handle`.
#[must_use]
pub fn guard(response: Response, handle: Arc<StreamHandle>) -> Response {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::new(Guarded::new(body, handle)))
}

/// The body of an event stream: the frames of the upstream until the registry closes the stream.
struct Guarded {
    inner: Body,
    closed: Pin<Box<dyn Future<Output = CloseReason> + Send>>,
    handle: Arc<StreamHandle>,
}

impl Guarded {
    fn new(inner: Body, handle: Arc<StreamHandle>) -> Self {
        Self {
            inner,
            closed: Box::pin(handle.closed()),
            handle,
        }
    }
}

impl HttpBody for Guarded {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        if this.closed.as_mut().poll(context).is_ready() {
            return Poll::Ready(None);
        }
        let polled = Pin::new(&mut this.inner).poll_frame(context);
        if matches!(polled, Poll::Ready(Some(Ok(_)))) {
            this.handle.activity().touch();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests;
