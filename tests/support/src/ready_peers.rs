//! Ready gateway pod count double.

use std::sync::atomic::{AtomicU32, Ordering};

use iam_domain::ReadyPeers;

/// A count of ready peers that a test sets.
#[derive(Debug, Default)]
pub struct FakeReadyPeers(AtomicU32);

impl FakeReadyPeers {
    /// A count of `ready` endpoints.
    #[must_use]
    pub const fn new(ready: u32) -> Self {
        Self(AtomicU32::new(ready))
    }

    /// Changes the count to `ready`.
    pub fn set(&self, ready: u32) {
        self.0.store(ready, Ordering::Relaxed);
    }
}

impl ReadyPeers for FakeReadyPeers {
    fn ready_endpoints(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
