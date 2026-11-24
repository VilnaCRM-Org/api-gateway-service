//! AZ-aware peer-relative readiness (FR-85, NFR-41, ADR 0028).
//!
//! A stale pod leaves the load balancer only when its peers are fresh, and a zone never loses its
//! last target: the [`PeerReadinessChecker`] task compares the pod with a sample of its peers
//! every [`CHECK_INTERVAL`], asks `FreshnessRule` for the verdict, applies the hysteresis and the
//! zone floor, and publishes the result in the [`ReadinessGate`] that the readiness probe and the
//! public listener read. When staleness is fleet-wide the pods stay ready and fail closed per
//! request.

pub mod checker;
#[cfg(test)]
mod fixtures;
pub mod gate;
pub mod peers;
pub mod sample;

pub use checker::{CHECK_INTERVAL, PeerReadinessChecker};
pub use gate::ReadinessGate;
pub use peers::{PEER_READ_TIMEOUT, PeerSet, PeerSetPorts};
pub use sample::{FULL_FLEET_BELOW, OWN_ZONE_SAMPLE, SAMPLE_SIZE, select_peers};
