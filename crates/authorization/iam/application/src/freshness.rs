//! The freshness of a pod (FR-73, NFR-36, ADR 0024).
//!
//! The shared state that every request reads, the attachment of probe proofs to published
//! snapshots, the cross-check against the peers and the `FreshnessProber` task that drives them.

pub mod attachment;
pub mod peer_lag;
pub mod prober;
pub mod state;

pub use attachment::ProofAttachment;
pub use peer_lag::{PEER_LAG_TOLERANCE, PeerLag, PeerLagTracker};
pub use prober::{FreshnessProber, ProberPorts, ProberSettings, ProofSink, WATCHDOG_INTERVAL};
pub use state::{FreshnessReading, FreshnessState};
