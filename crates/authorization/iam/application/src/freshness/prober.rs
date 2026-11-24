//! The `FreshnessProber` task (FR-73, NFR-36).
//!
//! Three loops share one pod: a probe of the state topic every `FRESHNESS_PROBE_INTERVAL`, whose
//! proof goes to the apply thread, a watchdog that ticks every second on the boot clock and
//! records the gaps a frozen or suspended process leaves, and the cross-check against the peers.
//! The steps are methods, so that a test drives each of them without waiting for a timer.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    BootClock, Freshness, PeerFreshnessClient, PolicyLogProbe, PolicyView, ProbeError, StaleCause,
};
use tokio::sync::watch;
use tokio::time::{Interval, MissedTickBehavior};

use super::peer_lag::{PeerLag, PeerLagTracker};
use super::state::FreshnessState;

/// The period of the watchdog tick.
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);

/// The period of the cross-check against the peers: short against the tolerance of one second, so
/// that a lag is seen soon after it exceeds it.
const PEER_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// Receives the proofs of the probe: the apply thread attaches one to a published snapshot once
/// the snapshot covers it.
pub trait ProofSink: std::fmt::Debug + Send + Sync {
    /// Hands a proof over; it never blocks.
    fn offer(&self, proof: FreshnessProof);
}

/// The ports of the prober.
#[derive(Debug, Clone)]
pub struct ProberPorts {
    /// Probes the state topic.
    pub probe: Arc<dyn PolicyLogProbe>,
    /// Asks the peers which version they applied.
    pub peers: Arc<dyn PeerFreshnessClient>,
    /// The published snapshot of this pod.
    pub view: Arc<dyn PolicyView>,
    /// The boot clock.
    pub clock: Arc<dyn BootClock>,
    /// Where the proofs go.
    pub sink: Arc<dyn ProofSink>,
    /// The freshness state of the pod.
    pub state: Arc<FreshnessState>,
}

/// The period of the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProberSettings {
    /// `FRESHNESS_PROBE_INTERVAL`.
    pub probe_interval: Duration,
}

/// The task that proves the freshness of the pod and watches it.
#[derive(Debug)]
pub struct FreshnessProber {
    ports: ProberPorts,
    settings: ProberSettings,
    lag: Mutex<PeerLagTracker>,
}

impl FreshnessProber {
    /// A prober over `ports`.
    #[must_use]
    pub const fn new(ports: ProberPorts, settings: ProberSettings) -> Self {
        Self {
            ports,
            settings,
            lag: Mutex::new(PeerLagTracker::new()),
        }
    }

    /// The name of the task, for the log entries of the supervisor.
    #[must_use]
    pub const fn name() -> &'static str {
        "freshness-prober"
    }

    /// One probe: a proof goes to the sink, a failure produces none and is logged.
    pub async fn probe_once(&self) {
        match self.ports.probe.probe().await {
            Ok(proof) => self.ports.sink.offer(proof),
            Err(error) => log_probe_failed(&error),
        }
    }

    /// One tick of the watchdog: the gap since the last tick is recorded, and the metric events
    /// of the pod are emitted.
    pub fn watchdog_tick(&self) {
        let gap = self.ports.state.tick();
        let rule = self.ports.state.rule();
        if let Some(gap) = gap.filter(|gap| rule.gap_breaks_proof(*gap)) {
            log_gap(gap, rule.ready_bound());
        }
        let reading = self.ports.state.reading();
        if let Some(age) = reading.proof_age {
            log_proof_age(age.as_secs_f64());
        }
        log_fresh(reading.verdict);
    }

    /// One cross-check: while the pod is fresh, a peer that has applied a newer version for longer
    /// than the tolerance invalidates the proof and alerts.
    pub async fn check_peers(&self) {
        let state = &self.ports.state;
        let own = self.ports.view.current().map(|snapshot| snapshot.version());
        let Some(own) = own.filter(|_version| state.is_fresh()) else {
            *self.tracker() = PeerLagTracker::new();
            return;
        };
        let peers = self.ports.peers.applied_versions().await;
        let observed = self.tracker().observe(self.ports.clock.now(), own, &peers);
        if let PeerLag::Exceeded { lag, peer, first } = observed {
            state.invalidate();
            if first {
                log_peer_ahead(own.value(), peer.value(), lag);
            }
        }
    }

    fn tracker(&self) -> std::sync::MutexGuard<'_, PeerLagTracker> {
        self.lag.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs the three loops until the stop flag is set.
    pub async fn run(self, stopping: watch::Receiver<bool>) {
        let prober = Arc::new(self);
        tokio::join!(
            prober.probe_loop(stopping.clone()),
            prober.watchdog_loop(stopping.clone()),
            prober.peer_loop(stopping),
        );
    }

    async fn probe_loop(&self, mut stopping: watch::Receiver<bool>) {
        let mut ticker = ticker(self.settings.probe_interval);
        while !ticked(&mut ticker, &mut stopping).await {
            tokio::select! {
                () = stopped(&mut stopping) => return,
                () = self.probe_once() => {}
            }
        }
    }

    async fn watchdog_loop(&self, mut stopping: watch::Receiver<bool>) {
        let mut ticker = ticker(WATCHDOG_INTERVAL);
        while !ticked(&mut ticker, &mut stopping).await {
            self.watchdog_tick();
        }
    }

    async fn peer_loop(&self, mut stopping: watch::Receiver<bool>) {
        let mut ticker = ticker(PEER_CHECK_INTERVAL);
        while !ticked(&mut ticker, &mut stopping).await {
            tokio::select! {
                () = stopped(&mut stopping) => return,
                () = self.check_peers() => {}
            }
        }
    }
}

fn ticker(period: Duration) -> Interval {
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

/// Completes when the stop flag is set.
async fn stopped(stopping: &mut watch::Receiver<bool>) {
    drop(stopping.wait_for(|stopping| *stopping).await);
}

/// Waits for the next tick; whether the stop flag is set instead.
async fn ticked(ticker: &mut Interval, stopping: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = stopped(stopping) => true,
        _instant = ticker.tick() => *stopping.borrow(),
    }
}

fn log_probe_failed(error: &ProbeError) {
    tracing::warn!(%error, "the freshness probe produced no proof");
}

fn log_gap(gap: Duration, ready_bound: Duration) {
    let gap_ms = u64::try_from(gap.as_millis()).unwrap_or(u64::MAX);
    let ready_ms = u64::try_from(ready_bound.as_millis()).unwrap_or(u64::MAX);
    tracing::warn!(
        gap_ms,
        ready_bound_ms = ready_ms,
        "the watchdog saw a gap above the ready bound; the proof is invalid until a new one is attached"
    );
}

fn log_proof_age(seconds: f64) {
    tracing::info!(
        metric = "policy_proof_age_seconds",
        seconds,
        "age of the freshness proof"
    );
}

/// The word that names why a pod is stale, or `fresh`.
const fn reason(verdict: Freshness) -> &'static str {
    match verdict {
        Freshness::Fresh(_age) => "fresh",
        Freshness::Stale(StaleCause::NoProof) => "no_proof",
        Freshness::Stale(StaleCause::Aged(_age)) => "aged",
        Freshness::Stale(StaleCause::Gap(_gap)) => "gap",
    }
}

fn log_fresh(verdict: Freshness) {
    let value = u8::from(verdict.is_fresh());
    let reason = reason(verdict);
    tracing::info!(
        metric = "policy_fresh",
        value,
        reason,
        "freshness of the pod"
    );
}

fn log_peer_ahead(own: i64, peer: i64, lag: Duration) {
    let lag_ms = u64::try_from(lag.as_millis()).unwrap_or(u64::MAX);
    tracing::error!(
        metric = "policy_peer_ahead",
        own,
        peer,
        lag_ms,
        "a peer applied a newer version for longer than the tolerance; the freshness proof is invalid"
    );
}

#[cfg(test)]
mod tests;
