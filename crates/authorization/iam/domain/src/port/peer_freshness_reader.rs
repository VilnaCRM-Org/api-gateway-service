//! Port that asks one gateway pod for its freshness (FR-85).

use crate::endpoint::UpstreamEndpoint;
use crate::freshness::peer_report::PeerObservation;

/// Reads `GET /internal/freshness` of one peer pod, taken from the ready endpoints of the peers
/// Service.
#[async_trait::async_trait]
pub trait PeerFreshnessReader: std::fmt::Debug + Send + Sync {
    /// What `peer` reports, `None` when it does not answer or its answer cannot be used.
    async fn read(&self, peer: &UpstreamEndpoint) -> Option<PeerObservation>;
}
