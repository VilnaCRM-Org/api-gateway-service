//! The peer-relative readiness verdicts of a pod (FR-85, NFR-41).
//!
//! A stale pod compares itself with the peers it sampled. [`judge`] names what it finds: a local
//! problem (most peers are fresh), a zone-shaped problem (most peers of its own zone are stale
//! while most peers of the other zones are fresh) or a fleet-wide one (no such majority of fresh
//! peers). [`AzFloor`] says which pods of a zone may never go unready for staleness.

use super::hysteresis::ReadinessPressure;
use super::peer_report::PeerReport;
use crate::endpoint::zone::Zone;

/// What a pod finds when it compares its freshness with its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessVerdict {
    /// The pod is fresh.
    Fresh,
    /// The pod is stale while most peers are fresh.
    Local,
    /// The pod's zone is stale while most peers of the other zones are fresh.
    AzShaped,
    /// Most peers are stale too, or no peer vouches for a fresh fleet.
    FleetWide,
}

impl ReadinessVerdict {
    /// Whether the pod is fresh.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// What the verdict asks of the readiness; `floor_protects` says whether the zone floor keeps
    /// the pod in the load balancer.
    #[must_use]
    pub const fn pressure(self, floor_protects: bool) -> ReadinessPressure {
        match self {
            Self::Fresh => ReadinessPressure::Settled,
            Self::FleetWide => ReadinessPressure::Hold,
            Self::Local | Self::AzShaped => {
                if floor_protects {
                    ReadinessPressure::Hold
                } else {
                    ReadinessPressure::Shed
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    fresh: usize,
    stale: usize,
}

impl Tally {
    const fn add(&mut self, current: bool) {
        if current {
            self.fresh = self.fresh.saturating_add(1);
        } else {
            self.stale = self.stale.saturating_add(1);
        }
    }

    const fn mostly_fresh(self) -> bool {
        self.fresh > self.stale
    }

    const fn mostly_stale(self) -> bool {
        self.stale > self.fresh
    }

    const fn merged(self, other: Self) -> Self {
        Self {
            fresh: self.fresh.saturating_add(other.fresh),
            stale: self.stale.saturating_add(other.stale),
        }
    }
}

/// The peers of the own zone and the peers of the other zones, counted apart.
fn tally(own_zone: Option<&Zone>, peers: &[PeerReport]) -> (Tally, Tally) {
    let mut own = Tally::default();
    let mut other = Tally::default();
    for peer in peers {
        let side = if peer.zone.as_ref() == own_zone {
            &mut own
        } else {
            &mut other
        };
        side.add(peer.current);
    }
    (own, other)
}

/// The verdict of a pod whose own proof is current or not (`own_current`), in `own_zone`, over the
/// `peers` that answered.
#[must_use]
pub fn judge(own_current: bool, own_zone: Option<&Zone>, peers: &[PeerReport]) -> ReadinessVerdict {
    if own_current {
        return ReadinessVerdict::Fresh;
    }
    let (own, other) = tally(own_zone, peers);
    if own.mostly_stale() && other.mostly_fresh() {
        ReadinessVerdict::AzShaped
    } else if own.merged(other).mostly_fresh() {
        ReadinessVerdict::Local
    } else {
        ReadinessVerdict::FleetWide
    }
}

/// What a pod knows about the ready pods of its own zone.
#[derive(Debug, Clone, Copy)]
pub struct ZoneRoster<'a> {
    /// The name of this pod, empty when it does not know it.
    pub pod: &'a str,
    /// Whether this pod is ready now.
    pub self_ready: bool,
    /// The names of the other ready pods of the zone.
    pub others_ready: &'a [String],
    /// How many sampled peers of the zone are fresh.
    pub fresh_peers: usize,
}

/// `READINESS_AZ_FLOOR`: the last ready pods of a zone never go unready for staleness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AzFloor(usize);

impl AzFloor {
    /// A floor of `pods` pods per zone.
    #[must_use]
    pub const fn new(pods: usize) -> Self {
        Self(pods)
    }

    /// The number of pods.
    #[must_use]
    pub const fn pods(self) -> usize {
        self.0
    }

    /// Whether the floor keeps this pod in the load balancer.
    ///
    /// A ready pod is protected while the zone has no more ready pods than the floor. Beyond that,
    /// the fresh peers of the zone count towards the floor, and the stale pods that are still
    /// needed are the ones with the smallest names, so pods that run the same check at the same
    /// time agree on which of them stay. A pod that is not ready is protected, and so returns,
    /// while the other pods of its zone fall short of the floor.
    #[must_use]
    pub fn protects(self, roster: &ZoneRoster<'_>) -> bool {
        let others = roster.others_ready.len();
        if !roster.self_ready {
            return others < self.0;
        }
        if others.saturating_add(1) <= self.0 {
            return true;
        }
        let needed = self.0.saturating_sub(roster.fresh_peers);
        let ahead = roster
            .others_ready
            .iter()
            .filter(|name| name.as_str() < roster.pod)
            .count();
        ahead < needed
    }
}

#[cfg(test)]
mod tests;
