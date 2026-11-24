//! The freshness of the gateway pod in the composition root (Story 9.5, FR-73, NFR-36).
//!
//! [`FreshnessAdapters`] holds the state every request reads, the probe of the state topic and the
//! peer set of the cross-check. The apply thread attaches the proofs to the published snapshot,
//! the `FreshnessProber` task produces and watches them, the public listener answers 503
//! `iam_stale` while the state is not fresh and `/internal/freshness` reports it.

use std::sync::Arc;
use std::time::Duration;

use iam_application::{FreshnessProber, FreshnessState, ProberPorts, ProberSettings, ProofSink};
use iam_domain::{BootClock, FreshnessRule, PeerFreshnessClient, PolicyLogProbe, PolicyView};
use iam_infrastructure::{EmptyPeerFreshnessClient, KrafkaPolicyLogProbe};

use crate::config::GatewayConfig;

/// What the freshness of the pod needs from the composition root.
#[derive(Debug, Clone)]
pub struct FreshnessAdapters {
    /// The proof the pod holds and the verdict it gives.
    pub state: Arc<FreshnessState>,
    /// Probes the state topic.
    pub probe: Arc<dyn PolicyLogProbe>,
    /// Asks the peers which version they applied.
    pub peers: Arc<dyn PeerFreshnessClient>,
    /// The boot clock of the state.
    pub clock: Arc<dyn BootClock>,
    /// `FRESHNESS_PROBE_INTERVAL`.
    pub probe_interval: Duration,
}

impl FreshnessAdapters {
    /// The production wiring: the probe reads the state topic under the principal `iam-gateway`,
    /// and the peer set is empty until `PolicyAdapters::comparing` replaces it with the sampled
    /// peers of the pod (Story 15.1).
    #[must_use]
    pub fn from_config(config: &GatewayConfig, clock: Arc<dyn BootClock>) -> Self {
        let rule = FreshnessRule::new(config.freshness_hard_bound, config.freshness_ready_bound);
        Self {
            state: Arc::new(FreshnessState::new(rule, Arc::clone(&clock))),
            probe: Arc::new(KrafkaPolicyLogProbe::new(
                config.kafka_tail.clone(),
                Arc::clone(&clock),
            )),
            peers: Arc::new(EmptyPeerFreshnessClient),
            clock,
            probe_interval: config.freshness_probe_interval,
        }
    }

    /// The prober task over these adapters, reading the snapshot of `view` and handing its proofs
    /// to `sink`.
    #[must_use]
    pub fn prober(&self, view: Arc<dyn PolicyView>, sink: Arc<dyn ProofSink>) -> FreshnessProber {
        FreshnessProber::new(
            ProberPorts {
                probe: Arc::clone(&self.probe),
                peers: Arc::clone(&self.peers),
                view,
                clock: Arc::clone(&self.clock),
                sink,
                state: Arc::clone(&self.state),
            },
            ProberSettings {
                probe_interval: self.probe_interval,
            },
        )
    }
}

#[cfg(test)]
mod tests;
