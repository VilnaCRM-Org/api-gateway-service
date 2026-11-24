//! The proof a pod holds and the verdict it gives.

use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock, BootInstant, Freshness, FreshnessRule, PolicyVersion, StaleCause};

/// What the pod holds: the proof attached to its snapshot, and what the watchdog saw since.
#[derive(Debug, Default)]
struct Held {
    proof: Option<FreshnessProof>,
    version: Option<PolicyVersion>,
    largest_gap: Duration,
    last_tick: Option<BootInstant>,
    /// The instant of the last invalidation or of the last watchdog gap above the ready bound: a
    /// proof taken at or before it says nothing about the time after it.
    barrier: Option<BootInstant>,
}

/// One reading of the state: the verdict and the facts behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessReading {
    /// The verdict of the rule.
    pub verdict: Freshness,
    /// The age of the proof, `None` while the pod holds none.
    pub proof_age: Option<Duration>,
    /// The version of the snapshot the proof was attached to.
    pub proven_version: Option<PolicyVersion>,
}

/// The freshness state of the pod: written by the apply thread (attach) and the prober (watchdog,
/// cross-check), read by every request and by `/internal/freshness`.
#[derive(Debug)]
pub struct FreshnessState {
    rule: FreshnessRule,
    clock: Arc<dyn BootClock>,
    created: BootInstant,
    held: RwLock<Held>,
}

fn read(lock: &RwLock<Held>) -> RwLockReadGuard<'_, Held> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write(lock: &RwLock<Held>) -> RwLockWriteGuard<'_, Held> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

impl FreshnessState {
    /// A state that holds no proof.
    #[must_use]
    pub fn new(rule: FreshnessRule, clock: Arc<dyn BootClock>) -> Self {
        Self {
            rule,
            created: clock.now(),
            clock,
            held: RwLock::new(Held::default()),
        }
    }

    /// The rule that judges the proof.
    #[must_use]
    pub const fn rule(&self) -> FreshnessRule {
        self.rule
    }

    /// Attaches `proof` to the snapshot at `version` and returns whether it was attached.
    ///
    /// A proof taken at or before the last invalidation, or the last gap of the watchdog above the
    /// ready bound, is refused: it was taken before the pod lost track of the time. A watchdog that
    /// has been silent for longer than the ready bound is such a gap, so the proof is refused too.
    /// An attached proof starts the gap counter with the silence since the last tick.
    pub fn attach(&self, proof: FreshnessProof, version: PolicyVersion) -> bool {
        let now = self.clock.now();
        let mut held = write(&self.held);
        let silent = held
            .last_tick
            .map_or(Duration::ZERO, |tick| now.saturating_since(tick));
        if self.rule.gap_breaks_proof(silent) {
            held.barrier = Some(now);
        }
        if held
            .barrier
            .is_some_and(|barrier| proof.taken_at <= barrier)
        {
            log_refused(&proof);
            return false;
        }
        held.proof = Some(proof);
        held.version = Some(version);
        held.largest_gap = silent;
        true
    }

    /// Records a tick of the watchdog; the gap since the previous tick, `None` for the first.
    pub fn tick(&self) -> Option<Duration> {
        let now = self.clock.now();
        let mut held = write(&self.held);
        let gap = held.last_tick.map(|tick| now.saturating_since(tick));
        if let Some(gap) = gap {
            held.largest_gap = held.largest_gap.max(gap);
            if self.rule.gap_breaks_proof(gap) {
                held.barrier = Some(now);
            }
        }
        held.last_tick = Some(now);
        gap
    }

    /// How long the watchdog has been silent: the time since its last tick, or since the state was
    /// created while it has not ticked yet.
    #[must_use]
    pub fn watchdog_silence(&self) -> Duration {
        let now = self.clock.now();
        let held = read(&self.held);
        now.saturating_since(held.last_tick.unwrap_or(self.created))
    }

    /// Withdraws the proof: the pod is stale until a new proof is attached.
    pub fn invalidate(&self) {
        let mut held = write(&self.held);
        held.proof = None;
        held.version = None;
        held.largest_gap = Duration::ZERO;
        held.barrier = Some(self.clock.now());
    }

    /// The verdict now.
    #[must_use]
    pub fn verdict(&self) -> Freshness {
        self.reading().verdict
    }

    /// The verdict now with the facts behind it.
    #[must_use]
    pub fn reading(&self) -> FreshnessReading {
        let now = self.clock.now();
        let held = read(&self.held);
        FreshnessReading {
            verdict: self.rule.judge(now, held.proof.as_ref(), held.largest_gap),
            proof_age: held.proof.as_ref().map(|proof| proof.age(now)),
            proven_version: held.version,
        }
    }

    /// Whether the pod may allow a request now.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.verdict().is_fresh()
    }

    /// Why the pod is stale, `None` while it is fresh.
    #[must_use]
    pub fn stale_cause(&self) -> Option<StaleCause> {
        match self.verdict() {
            Freshness::Fresh(_age) => None,
            Freshness::Stale(cause) => Some(cause),
        }
    }
}

fn log_refused(proof: &FreshnessProof) {
    tracing::debug!(
        taken_at = ?proof.taken_at,
        "a proof taken before the last invalidation or watchdog gap was not attached"
    );
}

#[cfg(test)]
mod tests;
