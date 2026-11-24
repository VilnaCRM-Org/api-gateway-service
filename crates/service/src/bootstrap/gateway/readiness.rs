//! The peer-relative readiness of the gateway pod in the composition root (Story 15.1, FR-85).
//!
//! [`ReadinessAdapters`] holds the peers the pod compares itself with, the gate that publishes the
//! outcome and the zone floor. The `PeerReadinessChecker` task drives the gate, the readiness
//! probe reads it, and the public listener sheds its connections while it says the pod is not
//! ready. The peers also feed the cross-check of the freshness proof (Story 9.5).

use std::sync::Arc;

use iam_application::{
    EndpointDirectory, FreshnessState, PeerReadinessChecker, PeerSet, PeerSetPorts, ReadinessGate,
};
use iam_domain::{AzFloor, FreshnessRule, PeerFreshnessReader, Rng, WatchTarget};
use iam_infrastructure::HyperPeerFreshnessClient;

use crate::config::GatewayConfig;

/// What the peer-relative readiness needs from the composition root.
#[derive(Debug, Clone)]
pub struct ReadinessAdapters {
    /// The peers of the pod, sampled and asked for their freshness.
    pub peers: Arc<PeerSet>,
    /// The readiness the comparison decides.
    pub gate: Arc<ReadinessGate>,
    /// `READINESS_AZ_FLOOR`.
    pub floor: AzFloor,
}

impl ReadinessAdapters {
    /// The production wiring: the peers are the ready pods of `peers` in the endpoint `directory`,
    /// asked over plain HTTP, sampled through `rng`.
    #[must_use]
    pub fn from_config(
        config: &GatewayConfig,
        directory: &EndpointDirectory,
        peers: WatchTarget,
        rng: Arc<dyn Rng>,
    ) -> Self {
        let reader: Arc<dyn PeerFreshnessReader> = Arc::new(HyperPeerFreshnessClient::new());
        Self::with(config, directory, peers, reader, rng)
    }

    /// The same wiring over `reader` and `rng`, which tests replace.
    #[must_use]
    pub fn with(
        config: &GatewayConfig,
        directory: &EndpointDirectory,
        peers: WatchTarget,
        reader: Arc<dyn PeerFreshnessReader>,
        rng: Arc<dyn Rng>,
    ) -> Self {
        Self {
            peers: Arc::new(PeerSet::new(PeerSetPorts {
                view: directory.view(),
                target: peers,
                pod: config.pod_name.clone(),
                reader,
                rng,
                rule: FreshnessRule::new(config.freshness_hard_bound, config.freshness_ready_bound),
            })),
            gate: Arc::new(ReadinessGate::new()),
            floor: AzFloor::new(config.readiness_az_floor),
        }
    }

    /// The checker task over these adapters, judging the freshness `state` of the pod.
    #[must_use]
    pub fn checker(&self, state: Arc<FreshnessState>) -> PeerReadinessChecker {
        PeerReadinessChecker::new(
            Arc::clone(&self.peers),
            state,
            Arc::clone(&self.gate),
            self.floor,
        )
    }
}

#[cfg(test)]
mod tests;
