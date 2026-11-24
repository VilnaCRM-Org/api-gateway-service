//! What a peer pod reported about its freshness (FR-85).

use std::time::Duration;

use super::rule::FreshnessRule;
use crate::endpoint::zone::Zone;
use crate::value_object::policy_version::PolicyVersion;

/// What `GET /internal/freshness` of a peer answered, before this pod judges it against its own
/// bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerObservation {
    /// The version the peer published, `None` while it holds no snapshot.
    pub version: Option<PolicyVersion>,
    /// Whether the peer's own rule finds it fresh.
    pub fresh: bool,
    /// The age of the peer's proof, `None` while it holds none.
    pub proof_age: Option<Duration>,
}

/// One peer in the readiness verdict: its zone and whether its proof is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReport {
    /// The zone of the peer, when the endpoint slice reports one.
    pub zone: Option<Zone>,
    /// The version the peer published, `None` while it holds no snapshot.
    pub version: Option<PolicyVersion>,
    /// Whether the peer is fresh with a proof no older than `FRESHNESS_READY_BOUND`.
    pub current: bool,
}

impl PeerReport {
    /// The report of a peer in `zone` that answered `observation`, judged by `rule`.
    #[must_use]
    pub fn judged(zone: Option<Zone>, observation: PeerObservation, rule: &FreshnessRule) -> Self {
        Self {
            zone,
            version: observation.version,
            current: rule.is_current(observation.fresh, observation.proof_age),
        }
    }
}
