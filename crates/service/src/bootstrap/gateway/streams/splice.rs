//! The relay of an upgraded WebSocket connection (Story 11.1).
//!
//! After the upstream answered `101`, the gateway answers the client `101` too and then copies
//! both directions of the two upgraded connections until one side ends or the registry closes the
//! stream. Frames are never parsed: they flow unchanged, and every byte that moves counts as
//! traffic for the idle timeout. A stream that the registry closes gets a WebSocket close frame
//! with the code of the reason before the connections are dropped.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf, copy_bidirectional};

use super::registry::{Activity, CloseReason, StreamHandle};

/// How long the close frame may take to reach a client that does not read.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// The two connections that become upgraded once both answered `101`.
#[derive(Debug)]
pub struct Upgrades {
    /// The connection of the client.
    pub client: OnUpgrade,
    /// The connection to the upstream endpoint.
    pub upstream: OnUpgrade,
}

/// A connection that notes the traffic that crosses it.
#[derive(Debug)]
struct Tracked<T> {
    inner: T,
    activity: Arc<Activity>,
}

impl<T> Tracked<T> {
    const fn new(inner: T, activity: Arc<Activity>) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Tracked<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        if polled.is_ready() {
            self.activity.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tracked<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(context, bytes);
        if polled.is_ready() {
            self.activity.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// The unmasked WebSocket close frame that a server sends with `code`.
#[must_use]
pub const fn close_frame(code: u16) -> [u8; 4] {
    let [high, low] = code.to_be_bytes();
    [0x88, 0x02, high, low]
}

/// Relays the upgraded connections of the stream of `handle` until one side ends or the registry
/// closes the stream. `guards` are the permits of the stream, held until the relay ends.
pub async fn run<G: Send>(upgrades: Upgrades, handle: Arc<StreamHandle>, guards: G) {
    let _held = guards;
    let Upgrades { client, upstream } = upgrades;
    let both = async { tokio::join!(client, upstream) };
    let joined = tokio::select! {
        both = both => both,
        _closed = handle.closed() => return,
    };
    let (Ok(client), Ok(upstream)) = joined else {
        return;
    };
    let activity = Arc::clone(handle.activity());
    let mut client = Tracked::new(TokioIo::new(client), Arc::clone(&activity));
    let mut upstream = Tracked::new(TokioIo::new(upstream), activity);
    relay(&mut client, &mut upstream, &handle).await;
}

/// Copies both directions until one side ends, or until the registry closes the stream, which
/// ends with the close frame to the client.
async fn relay<C, U>(client: &mut C, upstream: &mut U, handle: &StreamHandle)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        outcome = copy_bidirectional(&mut *client, upstream) => log_ended(&outcome),
        reason = handle.closed() => goodbye(client, reason).await,
    }
}

/// Sends the close frame of `reason` and shuts the connection down, within [`CLOSE_GRACE`].
async fn goodbye<W: AsyncWrite + Unpin>(client: &mut W, reason: CloseReason) {
    let frame = close_frame(reason.code());
    let sent = tokio::time::timeout(CLOSE_GRACE, async {
        client.write_all(&frame).await?;
        client.shutdown().await
    })
    .await;
    log_goodbye(reason, matches!(sent, Ok(Ok(()))));
}

fn log_ended(outcome: &io::Result<(u64, u64)>) {
    match outcome {
        Ok((to_upstream, to_client)) => log_copied(*to_upstream, *to_client),
        Err(error) => log_failed(error),
    }
}

fn log_copied(to_upstream: u64, to_client: u64) {
    tracing::debug!(to_upstream, to_client, "a WebSocket stream ended");
}

fn log_failed(error: &io::Error) {
    tracing::debug!(%error, "a WebSocket stream ended with an error");
}

fn log_goodbye(reason: CloseReason, delivered: bool) {
    let reason = reason.label();
    tracing::debug!(reason, delivered, "a WebSocket stream was closed");
}

#[cfg(test)]
mod tests;
