//! The probes of the gateway pod (Story 9.7, FR-54).
//!
//! [`PodStatus`] holds what the composition root learns while the pod comes up: the key set is
//! parsed, the configuration gates of the state topic passed, the bootstrap installed a verified
//! snapshot, and whether a fenced pod is rebootstrapping. [`PodProbes`] reads it together with the
//! [`FreshnessState`] and the published snapshot and answers the three probes:
//!
//! - startup passes once every condition of the start held, and then stays passed for the life of
//!   the pod, so a pod that fences later is never restarted for it;
//! - ready passes while the pod is started, not rebootstrapping, holds a published snapshot, the
//!   freshness rule finds it fresh and its proof is no older than `FRESHNESS_READY_BOUND`; with a
//!   [`ReadinessGate`] (Story 15.1) that age check is replaced by the peer-relative verdict: the pod
//!   is ready until the [`PeerReadinessChecker`](crate::PeerReadinessChecker) fails it;
//! - live passes while the watchdog of the freshness state ticked less than [`LIVENESS_LIMIT`]
//!   ago, and reads no dependency at all.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iam_domain::PolicyView;

use crate::freshness::FreshnessState;
use crate::peer_readiness::ReadinessGate;

/// The longest silence of the watchdog under which `/ping` still answers 200.
pub const LIVENESS_LIMIT: Duration = Duration::from_secs(10);

/// What is not yet true of a pod that is not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotStarted {
    /// The JWT key set is not parsed.
    #[error("the JWT key set is not parsed")]
    KeysNotParsed,
    /// The state topic has not passed the configuration gates.
    #[error("the state topic has not passed the configuration gates")]
    ConfigGatesPending,
    /// The bootstrap has not published a verified snapshot.
    #[error("the bootstrap has not published a verified snapshot")]
    NotBootstrapped,
    /// No freshness proof is attached to the published snapshot yet.
    #[error("no freshness proof is attached to the published snapshot")]
    NoProofAttached,
}

/// Why a pod is not ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotReady {
    /// The pod is not started.
    #[error("the pod is not started: {0}")]
    NotStarted(NotStarted),
    /// A fenced pod is rebootstrapping.
    #[error("the pod is rebootstrapping")]
    Rebootstrapping,
    /// The snapshot was withdrawn, so no request may be allowed.
    #[error("no snapshot is published")]
    NoSnapshot,
    /// The freshness rule finds the pod stale.
    #[error("the freshness rule finds the pod stale")]
    NotFresh,
    /// The proof is older than `FRESHNESS_READY_BOUND`.
    #[error("the freshness proof is older than the ready bound")]
    ProofAged,
    /// The pod is stale while its peers are fresh: it left the load balancer.
    #[error("the pod is stale while its peers are fresh")]
    StaleAgainstPeers,
}

/// The facts of the start of a pod, written by the composition root and read by the probes.
#[derive(Debug, Default)]
pub struct PodStatus {
    keys_parsed: AtomicBool,
    config_gates_passed: AtomicBool,
    bootstrapped: AtomicBool,
    rebootstrapping: AtomicBool,
    started: AtomicBool,
}

impl PodStatus {
    /// A status in which nothing has happened yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The JWT key set was parsed.
    pub fn mark_keys_parsed(&self) {
        self.keys_parsed.store(true, Ordering::Release);
    }

    /// The state topic passed the configuration gates (or none are configured).
    pub fn mark_config_gates_passed(&self) {
        self.config_gates_passed.store(true, Ordering::Release);
    }

    /// A bootstrap installed a verified snapshot.
    pub fn mark_bootstrapped(&self) {
        self.bootstrapped.store(true, Ordering::Release);
    }

    /// The tail fenced itself: the pod rebootstraps and is not ready until it has.
    pub fn begin_rebootstrap(&self) {
        self.rebootstrapping.store(true, Ordering::Release);
    }

    /// The rebootstrap installed a verified snapshot.
    pub fn end_rebootstrap(&self) {
        self.rebootstrapping.store(false, Ordering::Release);
    }

    /// Whether the JWT key set was parsed.
    #[must_use]
    pub fn are_keys_parsed(&self) -> bool {
        self.keys_parsed.load(Ordering::Acquire)
    }

    /// Whether the configuration gates of the state topic passed.
    #[must_use]
    pub fn are_config_gates_passed(&self) -> bool {
        self.config_gates_passed.load(Ordering::Acquire)
    }

    /// Whether a bootstrap installed a verified snapshot.
    #[must_use]
    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrapped.load(Ordering::Acquire)
    }

    /// Whether a fenced pod is rebootstrapping.
    #[must_use]
    pub fn is_rebootstrapping(&self) -> bool {
        self.rebootstrapping.load(Ordering::Acquire)
    }

    fn first_missing(&self) -> Option<NotStarted> {
        if !self.keys_parsed.load(Ordering::Acquire) {
            Some(NotStarted::KeysNotParsed)
        } else if !self.config_gates_passed.load(Ordering::Acquire) {
            Some(NotStarted::ConfigGatesPending)
        } else if !self.bootstrapped.load(Ordering::Acquire) {
            Some(NotStarted::NotBootstrapped)
        } else {
            None
        }
    }
}

/// The probes of one pod.
#[derive(Debug, Clone)]
pub struct PodProbes {
    status: Arc<PodStatus>,
    freshness: Arc<FreshnessState>,
    view: Arc<dyn PolicyView>,
    peer_readiness: Option<Arc<ReadinessGate>>,
}

impl PodProbes {
    /// The probes over `status`, `freshness` and the snapshot `view`.
    #[must_use]
    pub fn new(
        status: Arc<PodStatus>,
        freshness: Arc<FreshnessState>,
        view: Arc<dyn PolicyView>,
    ) -> Self {
        Self {
            status,
            freshness,
            view,
            peer_readiness: None,
        }
    }

    /// The same probes with the peer-relative readiness: the pod is ready until `gate` says it is
    /// not, and its own proof age no longer decides.
    #[must_use]
    pub fn with_peer_readiness(mut self, gate: Arc<ReadinessGate>) -> Self {
        self.peer_readiness = Some(gate);
        self
    }

    /// The startup probe.
    ///
    /// # Errors
    ///
    /// Returns the first condition of the start that does not hold yet. Once the probe passed it
    /// passes for good.
    pub fn startup(&self) -> Result<(), NotStarted> {
        if self.status.started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.check_start()?;
        self.status.started.store(true, Ordering::Release);
        Ok(())
    }

    fn check_start(&self) -> Result<(), NotStarted> {
        if let Some(missing) = self.status.first_missing() {
            return Err(missing);
        }
        if self.view.current().is_none() {
            return Err(NotStarted::NotBootstrapped);
        }
        if self.freshness.reading().proven_version.is_none() {
            return Err(NotStarted::NoProofAttached);
        }
        Ok(())
    }

    /// The readiness probe.
    ///
    /// # Errors
    ///
    /// Returns why the pod should not receive traffic now.
    pub fn ready(&self) -> Result<(), NotReady> {
        self.startup().map_err(NotReady::NotStarted)?;
        if self.status.is_rebootstrapping() {
            return Err(NotReady::Rebootstrapping);
        }
        if self.view.current().is_none() {
            return Err(NotReady::NoSnapshot);
        }
        if let Some(gate) = &self.peer_readiness {
            return if gate.is_ready() {
                Ok(())
            } else {
                Err(NotReady::StaleAgainstPeers)
            };
        }
        let reading = self.freshness.reading();
        if !reading.verdict.is_fresh() {
            return Err(NotReady::NotFresh);
        }
        match reading.proof_age {
            Some(age) if age <= self.freshness.rule().ready_bound() => Ok(()),
            _ => Err(NotReady::ProofAged),
        }
    }

    /// The liveness probe: the watchdog ticked less than [`LIVENESS_LIMIT`] ago.
    #[must_use]
    pub fn live(&self) -> bool {
        self.freshness.watchdog_silence() < LIVENESS_LIMIT
    }
}

#[cfg(test)]
mod tests;
