//! Which peers a pod asks (FR-85).
//!
//! A fleet of fewer than [`FULL_FLEET_BELOW`] pods is asked entirely; a larger one is sampled:
//! [`SAMPLE_SIZE`] peers, [`OWN_ZONE_SAMPLE`] of them in the zone of the pod, drawn through `Rng`.

use iam_domain::{Rng, UpstreamEndpoint, Zone};

/// A fleet with fewer pods than this is asked entirely.
pub const FULL_FLEET_BELOW: usize = 10;

/// How many peers a larger fleet is sampled to.
pub const SAMPLE_SIZE: usize = 5;

/// How many of the sampled peers lie in the zone of the pod, as far as the zone has them.
pub const OWN_ZONE_SAMPLE: usize = 3;

/// A draw below `bound`, 0 for an empty range.
fn below(rng: &dyn Rng, bound: usize) -> usize {
    let bound = u64::try_from(bound).unwrap_or(u64::MAX);
    let drawn = rng.next_u64().checked_rem(bound).unwrap_or(0);
    usize::try_from(drawn).unwrap_or(0)
}

/// A uniform shuffle of `items` (Fisher-Yates).
fn shuffle<T>(rng: &dyn Rng, items: &mut [T]) {
    for end in (1..items.len()).rev() {
        items.swap(end, below(rng, end.saturating_add(1)));
    }
}

/// The peers to ask out of `peers`, the ready peers other than the pod itself, for a pod in
/// `own_zone`.
///
/// The fleet is the peers and the pod. A fleet below [`FULL_FLEET_BELOW`] pods asks every peer.
/// Otherwise the sample holds up to [`OWN_ZONE_SAMPLE`] peers of the own zone, completed to
/// [`SAMPLE_SIZE`] from the other zones, and from the own zone again when the other zones have too
/// few.
#[must_use]
pub fn select_peers(
    rng: &dyn Rng,
    peers: Vec<UpstreamEndpoint>,
    own_zone: Option<&Zone>,
) -> Vec<UpstreamEndpoint> {
    if peers.len().saturating_add(1) < FULL_FLEET_BELOW {
        return peers;
    }
    let (mut own, mut other): (Vec<_>, Vec<_>) =
        peers.into_iter().partition(|peer| peer.zone() == own_zone);
    shuffle(rng, &mut own);
    shuffle(rng, &mut other);
    let kept = own.len().min(OWN_ZONE_SAMPLE);
    let mut sample: Vec<_> = own.drain(..kept).collect();
    sample.extend(
        other
            .into_iter()
            .take(SAMPLE_SIZE.saturating_sub(sample.len())),
    );
    sample.extend(
        own.into_iter()
            .take(SAMPLE_SIZE.saturating_sub(sample.len())),
    );
    sample
}

#[cfg(test)]
mod tests;
