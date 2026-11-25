//! The response body that the gateway relays (Story 10.5).
//!
//! It is the body of the upstream under the deadline of the whole request, and it holds the
//! concurrency permit of its upstream until the body ends or the caller drops it.

use std::future::Future as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Bytes;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use tokio::time::{Instant, Sleep, sleep_until};

use super::payload::BodyError;
use super::registry::Permit;

/// The whole request ran out of time while its response body was relayed.
#[derive(Debug, thiserror::Error)]
#[error("the request did not finish within its timeout")]
pub(super) struct RequestTimedOut;

/// The body of an upstream response, relayed as it arrives.
#[derive(Debug)]
pub(super) struct RelayBody {
    inner: Incoming,
    deadline: Option<Pin<Box<Sleep>>>,
    _permit: Permit,
}

impl RelayBody {
    /// The body of `inner`, which fails at `deadline` when there is one, and counts `permit`
    /// against the concurrency limit of its upstream while it lives.
    pub(super) fn new(inner: Incoming, deadline: Option<Instant>, permit: Permit) -> Self {
        Self {
            inner,
            deadline: deadline.map(|at| Box::pin(sleep_until(at))),
            _permit: permit,
        }
    }
}

impl HttpBody for RelayBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if let Some(deadline) = this.deadline.as_mut()
            && deadline.as_mut().poll(context).is_ready()
        {
            return Poll::Ready(Some(Err(RequestTimedOut.into())));
        }
        Pin::new(&mut this.inner)
            .poll_frame(context)
            .map_err(BodyError::from)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
