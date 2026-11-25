//! The wire check of the framing rules (Story 10.9, FR-67): the HTTP/1.1 server of the gateway
//! reads a request that carries both `Content-Length` and `Transfer-Encoding` as chunked and drops
//! the length header before any handler sees it, so the pipeline cannot tell that the client sent
//! two framings. [`Scanned`] reads the bytes of a connection as they arrive and records in a
//! [`WireFraming`] that a header block carried both headers; the framing middleware then answers
//! 400 to the request.
//!
//! A line that starts with a header name counts wherever it is, so a body that holds such a line
//! after a blank line can only make the gateway refuse more, never less.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The longest start of a line the scan keeps: enough for the longest header name it looks for.
const NAME_WINDOW: usize = 32;

const LENGTH: &[u8] = b"content-length:";
const ENCODING: &[u8] = b"transfer-encoding:";

/// Whether the bytes of a connection held a header block with both length headers.
#[derive(Debug, Default)]
pub struct WireFraming {
    conflict: AtomicBool,
}

impl WireFraming {
    /// Whether a header block of the connection carried `Content-Length` and `Transfer-Encoding`.
    #[must_use]
    pub fn conflicted(&self) -> bool {
        self.conflict.load(Ordering::Acquire)
    }

    pub(super) fn mark(&self) {
        self.conflict.store(true, Ordering::Release);
    }
}

/// The lines of the bytes read so far, and which length headers the current block has.
#[derive(Debug, Default)]
struct Lines {
    start: Vec<u8>,
    length: bool,
    encoding: bool,
}

impl Lines {
    /// Takes one byte; `true` when it completes a line that makes the block hold both headers.
    fn push(&mut self, byte: u8) -> bool {
        if byte != b'\n' {
            if self.start.len() < NAME_WINDOW {
                self.start.push(byte);
            }
            return false;
        }
        let line = self.start.strip_suffix(b"\r").unwrap_or(&self.start);
        if line.is_empty() {
            self.start.clear();
            self.length = false;
            self.encoding = false;
            return false;
        }
        let length = begins_with(line, LENGTH);
        let encoding = begins_with(line, ENCODING);
        self.start.clear();
        self.length |= length;
        self.encoding |= encoding;
        self.length && self.encoding
    }
}

fn begins_with(line: &[u8], name: &[u8]) -> bool {
    line.get(..name.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(name))
}

/// A connection that records in a [`WireFraming`] what its header blocks carried.
#[derive(Debug)]
pub struct Scanned<Io> {
    io: Io,
    lines: Lines,
    wire: Arc<WireFraming>,
}

impl<Io> Scanned<Io> {
    /// `io` read through the scan, and the record of what it found.
    #[must_use]
    pub fn new(io: Io) -> (Self, Arc<WireFraming>) {
        let wire = Arc::new(WireFraming::default());
        let scanned = Self {
            io,
            lines: Lines::default(),
            wire: Arc::clone(&wire),
        };
        (scanned, wire)
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for Scanned<Io> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buffer.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(context, buffer);
        if matches!(polled, Poll::Ready(Ok(()))) {
            let fresh = buffer.filled().get(before..).unwrap_or_default();
            if fresh.iter().any(|byte| this.lines.push(*byte)) {
                this.wire.mark();
            }
        }
        polled
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for Scanned<Io> {
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

#[cfg(test)]
mod tests;
