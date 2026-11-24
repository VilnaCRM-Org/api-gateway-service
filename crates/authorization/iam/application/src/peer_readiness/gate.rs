//! The readiness that the peer comparison decides.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

/// Whether the pod is ready, and whether it sheds its connections.
///
/// The [`PeerReadinessChecker`](super::PeerReadinessChecker) writes it; the readiness probe reads
/// [`ReadinessGate::is_ready`] and the public listener follows [`ReadinessGate::shedding`], which
/// is `true` while the pod is not ready: it sends HTTP/2 `GOAWAY` and `Connection: close` then.
#[derive(Debug)]
pub struct ReadinessGate {
    ready: AtomicBool,
    shedding: watch::Sender<bool>,
}

impl Default for ReadinessGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessGate {
    /// A gate of a pod that is ready.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
            shedding: watch::channel(false).0,
        }
    }

    /// Whether the pod is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Sets the readiness; a pod that is not ready sheds its connections.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
        self.shedding.send_replace(!ready);
    }

    /// A receiver that holds `true` while the pod sheds its connections.
    #[must_use]
    pub fn shedding(&self) -> watch::Receiver<bool> {
        self.shedding.subscribe()
    }
}

#[cfg(test)]
mod tests;
