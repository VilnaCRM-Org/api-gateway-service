//! The zone-aware power-of-two-choices rule that picks the endpoint of a request (FR-87,
//! NFR-43).
//!
//! The rule is pure: the in-flight counts and the random draws are inputs. Among the endpoints
//! offered for new requests it prefers the gateway's own zone, and spills to the other zones only
//! when the own zone has no offered endpoint or its in-flight load per endpoint exceeds the
//! threshold. Inside the chosen pool it draws two endpoints and takes the one with fewer
//! in-flight requests.

use super::UpstreamEndpoint;
use super::zone::Zone;
use crate::port::rng::Rng;

/// The in-flight requests per endpoint of the own zone above which requests spill to other zones
/// when the configuration does not choose a threshold.
pub const DEFAULT_SPILL_THRESHOLD: u32 = 64;

/// An endpoint with the number of requests the gateway has in flight to it.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// The endpoint.
    pub endpoint: &'a UpstreamEndpoint,
    /// The requests in flight to it.
    pub in_flight: u32,
}

/// Chooses an endpoint of a set of candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSelector {
    own_zone: Option<Zone>,
    zone_aware: bool,
    spill_threshold: u32,
}

impl EndpointSelector {
    /// A selector for a gateway pod in `own_zone`; `zone_aware` switches the zone preference off
    /// (`UPSTREAM_ZONE_AWARE=false`), which makes the pool every offered endpoint.
    #[must_use]
    pub const fn new(own_zone: Option<Zone>, zone_aware: bool, spill_threshold: u32) -> Self {
        Self {
            own_zone,
            zone_aware,
            spill_threshold,
        }
    }

    /// The index in `candidates` of the endpoint for a new request, or `None` when no candidate
    /// is offered (ready and not terminating).
    #[must_use]
    pub fn select(&self, candidates: &[Candidate<'_>], rng: &dyn Rng) -> Option<usize> {
        let offered: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate.endpoint.is_offered())
            .map(|(index, _)| index)
            .collect();
        let pool = self.pool(candidates, offered);
        two_choices(candidates, &pool, rng)
    }

    /// The offered endpoints a request may go to: the own zone, or the others when the own zone
    /// has none or is overloaded.
    fn pool(&self, candidates: &[Candidate<'_>], offered: Vec<usize>) -> Vec<usize> {
        let Some(zone) = self.own_zone.as_ref().filter(|_| self.zone_aware) else {
            return offered;
        };
        let (own, others): (Vec<usize>, Vec<usize>) = offered.into_iter().partition(|&index| {
            candidates
                .get(index)
                .is_some_and(|candidate| candidate.endpoint.zone() == Some(zone))
        });
        if own.is_empty() || (!others.is_empty() && self.overloaded(candidates, &own)) {
            others
        } else {
            own
        }
    }

    /// Whether the in-flight requests per endpoint of `own` exceed the threshold.
    fn overloaded(&self, candidates: &[Candidate<'_>], own: &[usize]) -> bool {
        let total: u64 = own
            .iter()
            .filter_map(|&index| candidates.get(index))
            .map(|candidate| u64::from(candidate.in_flight))
            .sum();
        let count = u64::try_from(own.len()).unwrap_or(u64::MAX);
        total.checked_div(count).unwrap_or(0) > u64::from(self.spill_threshold)
    }
}

/// Power of two choices over `pool`: two distinct draws, the one with fewer requests in flight
/// wins and the first draw wins a tie.
fn two_choices(candidates: &[Candidate<'_>], pool: &[usize], rng: &dyn Rng) -> Option<usize> {
    let size = pool.len();
    if size < 2 {
        return pool.first().copied();
    }
    let first = below(rng, size);
    let skipped = below(rng, size.saturating_sub(1));
    let second = if skipped >= first {
        skipped.saturating_add(1)
    } else {
        skipped
    };
    let (first, second) = (pool.get(first).copied()?, pool.get(second).copied()?);
    let load = |index: usize| {
        candidates
            .get(index)
            .map_or(u32::MAX, |candidate| candidate.in_flight)
    };
    Some(if load(second) < load(first) {
        second
    } else {
        first
    })
}

/// A draw below `bound` (at least 1).
fn below(rng: &dyn Rng, bound: usize) -> usize {
    let bound = u64::try_from(bound).unwrap_or(u64::MAX);
    let drawn = rng.next_u64().checked_rem(bound).unwrap_or(0);
    usize::try_from(drawn).unwrap_or(0)
}

#[cfg(test)]
mod tests;
