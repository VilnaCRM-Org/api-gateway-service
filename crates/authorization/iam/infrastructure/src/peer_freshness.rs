//! The adapters of the peer freshness ports.
//!
//! [`HyperPeerFreshnessClient`] reads `GET /internal/freshness` of one gateway pod over plain
//! HTTP (FR-85). [`EmptyPeerFreshnessClient`] is a peer set with no peer, for the pods and tests
//! that run without the endpoint discovery of their peers: the cross-check of the freshness proof
//! is inactive there.

pub mod hyper_client;

use iam_domain::{PeerFreshnessClient, PolicyVersion};

pub use hyper_client::HyperPeerFreshnessClient;

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
