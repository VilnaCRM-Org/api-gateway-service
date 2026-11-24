//! `FreshnessRule`: when a pod may allow a request (FR-73, NFR-36).

use std::time::Duration;

use super::peer_report::PeerReport;
use super::proof::FreshnessProof;
use super::readiness::{self, ReadinessVerdict};
use crate::endpoint::zone::Zone;
use crate::value_object::boot_instant::BootInstant;

/// Why a pod is not fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleCause {
    /// No proof is attached to the published snapshot.
    NoProof,
    /// The proof is older than `FRESHNESS_HARD_BOUND`.
    Aged(Duration),
    /// The watchdog saw a gap above `FRESHNESS_READY_BOUND` since the proof.
    Gap(Duration),
}

/// The verdict of the rule at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The pod may allow; the proof is this old.
    Fresh(Duration),
    /// The pod answers 503 `iam_stale`.
    Stale(StaleCause),
}

impl Freshness {
    /// Whether the pod may allow.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh(_))
    }
}

/// Allow only while `now - last proof <= hard bound` and the watchdog showed no gap above the
/// ready bound since that proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessRule {
    hard_bound: Duration,
    ready_bound: Duration,
}

impl FreshnessRule {
    /// A rule with `FRESHNESS_HARD_BOUND` and `FRESHNESS_READY_BOUND`.
    #[must_use]
    pub const fn new(hard_bound: Duration, ready_bound: Duration) -> Self {
        Self {
            hard_bound,
            ready_bound,
        }
    }

    /// `FRESHNESS_HARD_BOUND`.
    #[must_use]
    pub const fn hard_bound(&self) -> Duration {
        self.hard_bound
    }

    /// `FRESHNESS_READY_BOUND`.
    #[must_use]
    pub const fn ready_bound(&self) -> Duration {
        self.ready_bound
    }

    /// Whether a gap between two ticks of the watchdog breaks the proof it spans.
    #[must_use]
    pub fn gap_breaks_proof(&self, gap: Duration) -> bool {
        gap > self.ready_bound
    }

    /// Whether a pod with the verdict `fresh` and a proof of age `proof_age` counts as current for
    /// the peer comparison: fresh, and a proof no older than `FRESHNESS_READY_BOUND`.
    #[must_use]
    pub fn is_current(&self, fresh: bool, proof_age: Option<Duration>) -> bool {
        fresh && proof_age.is_some_and(|age| age <= self.ready_bound)
    }

    /// The readiness verdict of a pod that is `own_current` or not, in `own_zone`, after it asked
    /// the `peers` (FR-85): local, zone-shaped or fleet-wide.
    #[must_use]
    pub fn readiness_verdict(
        own_current: bool,
        own_zone: Option<&Zone>,
        peers: &[PeerReport],
    ) -> ReadinessVerdict {
        readiness::judge(own_current, own_zone, peers)
    }

    /// The verdict at `now` for `proof`, given the largest gap the watchdog saw since it.
    #[must_use]
    pub fn judge(
        &self,
        now: BootInstant,
        proof: Option<&FreshnessProof>,
        largest_gap: Duration,
    ) -> Freshness {
        let Some(proof) = proof else {
            return Freshness::Stale(StaleCause::NoProof);
        };
        let age = proof.age(now);
        if age > self.hard_bound {
            Freshness::Stale(StaleCause::Aged(age))
        } else if self.gap_breaks_proof(largest_gap) {
            Freshness::Stale(StaleCause::Gap(largest_gap))
        } else {
            Freshness::Fresh(age)
        }
    }
}

#[cfg(test)]
mod tests;
