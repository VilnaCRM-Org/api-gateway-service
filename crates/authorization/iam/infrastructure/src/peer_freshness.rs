//! The adapters of the peer freshness port.
//!
//! Until Story 15.1 wires the HTTP client that asks the peer pods, the composition root passes an
//! empty peer set, so the cross-check of the freshness proof is inactive.

use iam_domain::{PeerFreshnessClient, PolicyVersion};

/// A peer set with no peer: it reports no applied version.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyPeerFreshnessClient;

#[async_trait::async_trait]
impl PeerFreshnessClient for EmptyPeerFreshnessClient {
    async fn applied_versions(&self) -> Vec<PolicyVersion> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
