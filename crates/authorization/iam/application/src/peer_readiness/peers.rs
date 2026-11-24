//! The peers a pod compares itself with (FR-85, FR-73).
//!
//! A [`PeerSet`] reads the ready pods of `iam-gateway-peers` from the endpoint directory, samples
//! them through [`select_peers`](super::select_peers) and asks each sampled pod for its freshness.
//! It serves the readiness verdict with the [`PeerReport`] of every answer and the cross-check of
//! the freshness proof (Story 9.5) with their versions.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    FreshnessRule, PeerFreshnessClient, PeerFreshnessReader, PeerReport, PolicyVersion, Rng,
    UpstreamEndpoint, WatchTarget, Zone,
};
use tokio::task::JoinSet;

use super::sample::select_peers;
use crate::endpoint_directory::EndpointView;

/// How long one peer may take to answer before it is left out of the verdict.
pub const PEER_READ_TIMEOUT: Duration = Duration::from_millis(500);

/// What a [`PeerSet`] needs.
#[derive(Debug, Clone)]
pub struct PeerSetPorts {
    /// The endpoint directory the `EndpointWatcher` fills.
    pub view: EndpointView,
    /// The peers Service (`iam-gateway-peers`).
    pub target: WatchTarget,
    /// The name of this pod (`POD_NAME`), when the downward API provides it.
    pub pod: Option<String>,
    /// Asks one peer for its freshness.
    pub reader: Arc<dyn PeerFreshnessReader>,
    /// Draws the sample.
    pub rng: Arc<dyn Rng>,
    /// Judges the answers against `FRESHNESS_READY_BOUND`.
    pub rule: FreshnessRule,
}

/// The peers of a gateway pod.
#[derive(Debug, Clone)]
pub struct PeerSet {
    ports: PeerSetPorts,
}

impl PeerSet {
    /// A peer set over `ports`.
    #[must_use]
    pub const fn new(ports: PeerSetPorts) -> Self {
        Self { ports }
    }

    /// The name of this pod, empty when it does not know it.
    #[must_use]
    pub fn pod(&self) -> &str {
        self.ports.pod.as_deref().unwrap_or_default()
    }

    /// The zone of this pod, when known.
    #[must_use]
    pub fn own_zone(&self) -> Option<Zone> {
        self.ports.view.own_zone()
    }

    /// The ready peers other than this pod.
    fn others(&self) -> Vec<UpstreamEndpoint> {
        let pod = self.ports.pod.as_deref();
        let mut peers = self.ports.view.offered(&self.ports.target);
        peers.retain(|peer| pod.is_none() || peer.pod() != pod);
        peers
    }

    /// The names of the other ready pods of this pod's zone.
    #[must_use]
    pub fn zone_pods(&self) -> Vec<String> {
        let zone = self.own_zone();
        self.others()
            .into_iter()
            .filter(|peer| peer.zone() == zone.as_ref())
            .filter_map(|peer| peer.pod().map(str::to_owned))
            .collect()
    }

    /// Asks the sampled peers and returns what the ones that answered reported.
    pub async fn reports(&self) -> Vec<PeerReport> {
        let zone = self.own_zone();
        let sample = select_peers(self.ports.rng.as_ref(), self.others(), zone.as_ref());
        let mut asked = JoinSet::new();
        for peer in sample {
            let reader = Arc::clone(&self.ports.reader);
            let rule = self.ports.rule;
            asked.spawn(async move { ask(reader.as_ref(), &peer, &rule).await });
        }
        let mut reports = Vec::new();
        while let Some(answer) = asked.join_next().await {
            if let Ok(Some(report)) = answer {
                reports.push(report);
            }
        }
        reports
    }

    async fn versions(&self) -> Vec<PolicyVersion> {
        self.reports()
            .await
            .into_iter()
            .filter_map(|report| report.version)
            .collect()
    }
}

/// One peer's answer, `None` when it did not answer within [`PEER_READ_TIMEOUT`].
async fn ask(
    reader: &dyn PeerFreshnessReader,
    peer: &UpstreamEndpoint,
    rule: &FreshnessRule,
) -> Option<PeerReport> {
    let observation = tokio::time::timeout(PEER_READ_TIMEOUT, reader.read(peer))
        .await
        .ok()??;
    Some(PeerReport::judged(peer.zone().cloned(), observation, rule))
}

#[async_trait::async_trait]
impl PeerFreshnessClient for PeerSet {
    async fn applied_versions(&self) -> Vec<PolicyVersion> {
        self.versions().await
    }
}

#[cfg(test)]
mod tests;
