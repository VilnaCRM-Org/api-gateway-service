//! A double of the peers of a gateway pod: the versions they report, set by the test.

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{PeerFreshnessClient, PolicyVersion};

/// Peers that report the versions the test sets; none at first.
#[derive(Debug, Default)]
pub struct FakePeerFreshnessClient {
    versions: Mutex<Vec<PolicyVersion>>,
}

impl FakePeerFreshnessClient {
    /// A peer set that reports nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// From now on the peers report `versions`.
    pub fn report(&self, versions: Vec<PolicyVersion>) {
        *self.versions.lock().unwrap_or_else(PoisonError::into_inner) = versions;
    }
}

#[async_trait]
impl PeerFreshnessClient for FakePeerFreshnessClient {
    async fn applied_versions(&self) -> Vec<PolicyVersion> {
        self.versions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests;
