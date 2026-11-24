//! The `PeerReadinessChecker` task (FR-85).
//!
//! Every [`CHECK_INTERVAL`] the pod asks its sampled peers for their freshness and compares it
//! with its own: `FreshnessRule` names the verdict, [`AzFloor`] says whether the zone floor keeps
//! the pod in the load balancer, and [`ReadinessHysteresis`] turns the stream of verdicts into the
//! readiness the [`ReadinessGate`] publishes. The step is a method, so that a test drives it
//! without waiting for the timer.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{
    AzFloor, FreshnessRule, PeerReport, ReadinessHysteresis, ReadinessPressure,
    ReadinessTransition, ReadinessVerdict, Zone, ZoneRoster,
};
use tokio::sync::watch;
use tokio::time::{Interval, MissedTickBehavior};

use super::gate::ReadinessGate;
use super::peers::PeerSet;
use crate::freshness::FreshnessState;

/// The period of the comparison with the peers.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// The task that drives the readiness of the pod from its peers.
#[derive(Debug)]
pub struct PeerReadinessChecker {
    peers: Arc<PeerSet>,
    state: Arc<FreshnessState>,
    gate: Arc<ReadinessGate>,
    floor: AzFloor,
    hysteresis: Mutex<ReadinessHysteresis>,
}

impl PeerReadinessChecker {
    /// A checker over the `peers`, the `state` of the pod and the `gate` it drives, under the zone
    /// `floor`.
    #[must_use]
    pub const fn new(
        peers: Arc<PeerSet>,
        state: Arc<FreshnessState>,
        gate: Arc<ReadinessGate>,
        floor: AzFloor,
    ) -> Self {
        Self {
            peers,
            state,
            gate,
            floor,
            hysteresis: Mutex::new(ReadinessHysteresis::new()),
        }
    }

    /// The name of the task, for the log entries of the supervisor.
    #[must_use]
    pub const fn name() -> &'static str {
        "peer-readiness-checker"
    }

    /// One check: asks the peers, judges, and moves the gate when the hysteresis says so.
    pub async fn check_once(&self) -> ReadinessTransition {
        let reports = self.peers.reports().await;
        let zone = self.peers.own_zone();
        let reading = self.state.reading();
        let own_current = self
            .state
            .rule()
            .is_current(reading.verdict.is_fresh(), reading.proof_age);
        let verdict = FreshnessRule::readiness_verdict(own_current, zone.as_ref(), &reports);
        let protected = !verdict.is_fresh() && self.floor_protects(&reports, zone.as_ref());
        let transition = self.step(verdict, protected);
        log_verdict(verdict, protected, reports.len());
        transition
    }

    /// Whether the zone floor keeps this pod in the load balancer.
    fn floor_protects(&self, reports: &[PeerReport], zone: Option<&Zone>) -> bool {
        let others = self.peers.zone_pods();
        let fresh_peers = reports
            .iter()
            .filter(|report| report.current && report.zone.as_ref() == zone)
            .count();
        self.floor.protects(&ZoneRoster {
            pod: self.peers.pod(),
            self_ready: self.gate.is_ready(),
            others_ready: &others,
            fresh_peers,
        })
    }

    fn step(&self, verdict: ReadinessVerdict, protected: bool) -> ReadinessTransition {
        let (transition, ready) = self.advance(verdict.pressure(protected));
        if transition != ReadinessTransition::Unchanged {
            self.gate.set_ready(ready);
        }
        log_transition(transition);
        transition
    }

    /// Takes the pressure into the hysteresis; the transition and the readiness after it.
    fn advance(&self, pressure: ReadinessPressure) -> (ReadinessTransition, bool) {
        let mut hysteresis = self
            .hysteresis
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let transition = hysteresis.step(pressure);
        (transition, hysteresis.is_ready())
    }

    /// Checks every [`CHECK_INTERVAL`] until the stop flag is set.
    pub async fn run(self, mut stopping: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stopped(&mut stopping) => return,
                _transition = self.next_check(&mut ticker) => {}
            }
        }
    }

    /// Waits for the next tick and checks.
    async fn next_check(&self, ticker: &mut Interval) -> ReadinessTransition {
        ticker.tick().await;
        self.check_once().await
    }
}

/// Completes when the stop flag is set.
async fn stopped(stopping: &mut watch::Receiver<bool>) {
    drop(stopping.wait_for(|stopping| *stopping).await);
}

/// The word that names the verdict.
const fn reason(verdict: ReadinessVerdict) -> &'static str {
    match verdict {
        ReadinessVerdict::Fresh => "fresh",
        ReadinessVerdict::Local => "local",
        ReadinessVerdict::AzShaped => "az_shaped",
        ReadinessVerdict::FleetWide => "fleet_wide",
    }
}

fn log_verdict(verdict: ReadinessVerdict, protected: bool, peers: usize) {
    let reason = reason(verdict);
    tracing::debug!(
        metric = "policy_readiness_verdict",
        reason,
        protected,
        peers,
        "peer-relative readiness verdict"
    );
}

fn log_transition(transition: ReadinessTransition) {
    match transition {
        ReadinessTransition::BecameUnready => log_unready(),
        ReadinessTransition::BecameReady => log_ready(),
        ReadinessTransition::Unchanged => {}
    }
}

fn log_unready() {
    tracing::warn!(
        metric = "policy_ready",
        value = 0_u8,
        "the pod is stale while its peers are fresh; it fails readiness and sheds its connections"
    );
}

fn log_ready() {
    tracing::info!(
        metric = "policy_ready",
        value = 1_u8,
        "the pod is ready again"
    );
}

#[cfg(test)]
mod tests;
