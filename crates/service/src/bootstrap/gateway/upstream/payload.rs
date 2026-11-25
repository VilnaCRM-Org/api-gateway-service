//! The request body of the attempts of one request (Story 10.5).
//!
//! A body below 64 KiB whose length is declared is buffered when the request may be retried after
//! it was sent, so that every attempt sends the same bytes. Any other body is streamed from the
//! caller and shared between the attempts: a request that failed before the body was read, as a
//! refused connection does, sends it on the next attempt, and one that consumed part of it cannot
//! be sent again.

use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use iam_domain::{ForwardError, MAX_BUFFERED_BODY_BYTES, RequestBody};

/// The error of a request body that fails while it is sent.
pub(super) type BodyError = Box<dyn StdError + Send + Sync>;

/// The body of the caller under the body limit of the route, shared between attempts.
#[derive(Debug)]
pub(super) struct Streamed {
    body: Mutex<Limited<Body>>,
    polled: AtomicBool,
}

impl Streamed {
    fn poll_frame(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.polled.store(true, Ordering::Release);
        let mut body = self.body.lock().unwrap_or_else(PoisonError::into_inner);
        Pin::new(&mut *body).poll_frame(context)
    }

    fn size_hint(&self) -> SizeHint {
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_end_stream()
    }
}

/// What every attempt of a request sends.
#[derive(Debug, Clone)]
pub(super) enum Payload {
    /// The request has no body.
    Empty,
    /// The body is in memory and goes out whole on every attempt.
    Buffered(Bytes),
    /// The body is streamed from the caller.
    Streamed(Arc<Streamed>),
}

impl Payload {
    /// The payload of `body` under `limit` bytes. With `buffer`, a body of a declared length below
    /// [`MAX_BUFFERED_BODY_BYTES`] is read into memory first.
    ///
    /// # Errors
    ///
    /// [`ForwardError::BodyTooLarge`] when a buffered body exceeds `limit`, and
    /// [`ForwardError::Upstream`] when the caller's body fails while it is read.
    pub(super) async fn prepare(
        body: Body,
        limit: u64,
        buffer: bool,
    ) -> Result<Self, ForwardError> {
        if body.is_end_stream() {
            return Ok(Self::Empty);
        }
        let declared = body.size_hint().exact();
        let limited = Limited::new(body, usize::try_from(limit).unwrap_or(usize::MAX));
        if buffer && declared.is_some_and(|bytes| bytes < MAX_BUFFERED_BODY_BYTES) {
            return Self::buffered(limited).await;
        }
        Ok(Self::Streamed(Arc::new(Streamed {
            body: Mutex::new(limited),
            polled: AtomicBool::new(false),
        })))
    }

    async fn buffered(limited: Limited<Body>) -> Result<Self, ForwardError> {
        match limited.collect().await {
            Ok(collected) => Ok(Self::Buffered(collected.to_bytes())),
            Err(error) if error.is::<LengthLimitError>() => Err(ForwardError::BodyTooLarge),
            Err(_error) => Err(ForwardError::Upstream),
        }
    }

    /// The body as the retry rule sees it.
    pub(super) fn kind(&self) -> RequestBody {
        match self {
            Self::Empty => RequestBody::Empty,
            Self::Buffered(bytes) => {
                RequestBody::Buffered(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            }
            Self::Streamed(_) => RequestBody::Streamed,
        }
    }

    /// Whether another attempt can send the whole body: always for an empty or buffered one, and
    /// for a streamed one only while no attempt has read from it.
    pub(super) fn replayable(&self) -> bool {
        match self {
            Self::Empty | Self::Buffered(_) => true,
            Self::Streamed(streamed) => !streamed.polled.load(Ordering::Acquire),
        }
    }

    /// The body of one attempt.
    pub(super) fn body(&self) -> ReplayBody {
        ReplayBody {
            source: match self {
                Self::Empty => Source::Empty,
                Self::Buffered(bytes) => Source::Bytes(Some(bytes.clone())),
                Self::Streamed(streamed) => Source::Stream(Arc::clone(streamed)),
            },
        }
    }
}

#[derive(Debug)]
enum Source {
    Empty,
    Bytes(Option<Bytes>),
    Stream(Arc<Streamed>),
}

/// The body that one attempt hands to the client.
#[derive(Debug)]
pub(super) struct ReplayBody {
    source: Source,
}

impl HttpBody for ReplayBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match &mut self.get_mut().source {
            Source::Empty => Poll::Ready(None),
            Source::Bytes(slot) => Poll::Ready(slot.take().map(|bytes| Ok(Frame::data(bytes)))),
            Source::Stream(streamed) => streamed.poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.source {
            Source::Empty => true,
            Source::Bytes(slot) => slot.is_none(),
            Source::Stream(streamed) => streamed.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.source {
            Source::Empty => SizeHint::with_exact(0),
            Source::Bytes(slot) => SizeHint::with_exact(
                slot.as_ref()
                    .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            ),
            Source::Stream(streamed) => streamed.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests;
