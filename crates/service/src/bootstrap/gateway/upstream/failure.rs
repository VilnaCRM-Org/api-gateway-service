//! Why an attempt to reach an endpoint failed, and whether the request provably did not reach it
//! (Story 10.5).

use std::error::Error as StdError;

use http_body_util::LengthLimitError;
use hyper_util::client::legacy::Error as ClientError;
use iam_domain::{Delivery, ForwardError};

use super::ConnectTimedOut;

/// What the HTTP/2 library says of a stream that the server refused before it processed any of
/// it (`REFUSED_STREAM`).
const REFUSED_STREAM: &str =
    "stream error received: refused stream before processing any application logic";

/// What the HTTP/2 library says of a stream that the server's graceful GOAWAY (`NO_ERROR`) left
/// above its last stream id: the server never began it.
const GOAWAY_ABOVE_LAST_STREAM: &str = "connection error received: not a result of an error";

/// The verdict on a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Classified {
    /// The error the caller sees when the request is not retried.
    pub(super) error: ForwardError,
    /// Whether the request provably did not reach the endpoint.
    pub(super) delivery: Delivery,
    /// Whether the failure is a connect error, which counts towards the ejection of the endpoint.
    pub(super) connect: bool,
}

impl Classified {
    const fn connect(error: ForwardError) -> Self {
        Self {
            error,
            delivery: Delivery::NotSent,
            connect: true,
        }
    }

    const fn unsent(error: ForwardError) -> Self {
        Self {
            error,
            delivery: Delivery::NotSent,
            connect: false,
        }
    }

    const fn possibly_sent(error: ForwardError) -> Self {
        Self {
            error,
            delivery: Delivery::MaybeSent,
            connect: false,
        }
    }
}

/// The verdict on `error`, which the client returned for a request.
pub(super) fn classify(error: &ClientError) -> Classified {
    let root: &(dyn StdError + 'static) = error;
    let causes: Vec<&(dyn StdError + 'static)> =
        std::iter::successors(Some(root), |&cause| cause.source()).collect();
    if causes.iter().any(|cause| cause.is::<LengthLimitError>()) {
        Classified::possibly_sent(ForwardError::BodyTooLarge)
    } else if causes.iter().any(|cause| cause.is::<ConnectTimedOut>()) {
        Classified::connect(ForwardError::ConnectTimeout)
    } else if error.is_connect() {
        Classified::connect(ForwardError::NotSent)
    } else if causes.iter().any(|cause| never_began(*cause))
        && !causes.iter().any(|cause| closed_midway(*cause))
    {
        Classified::unsent(ForwardError::NotSent)
    } else {
        Classified::possibly_sent(ForwardError::Upstream)
    }
}

/// Whether `cause` says that the connection closed before the response was complete. The client
/// reports such a request as canceled as well, but the server had it: only a request that was
/// dropped before a write is canceled without this cause.
fn closed_midway(cause: &(dyn StdError + 'static)) -> bool {
    cause
        .downcast_ref::<hyper::Error>()
        .is_some_and(hyper::Error::is_incomplete_message)
}

/// Whether `cause` says that the request was dropped before a write, or that the server refused
/// the stream or never began it.
fn never_began(cause: &(dyn StdError + 'static)) -> bool {
    let canceled = cause
        .downcast_ref::<hyper::Error>()
        .is_some_and(hyper::Error::is_canceled);
    canceled || refused_text(&cause.to_string())
}

/// Whether the text of an HTTP/2 error is a refused stream or a graceful GOAWAY.
fn refused_text(text: &str) -> bool {
    text.contains(REFUSED_STREAM) || text.contains(GOAWAY_ABOVE_LAST_STREAM)
}

#[cfg(test)]
mod tests;
