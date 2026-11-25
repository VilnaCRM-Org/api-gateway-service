//! The breaker of the shared rate counters (FR-65, NFR-42).
//!
//! After [`BREAKER_FAILURE_THRESHOLD`] consecutive failed or timed-out calls the breaker opens for
//! `RATE_LIMIT_BREAKER_OPEN_DURATION`. While it is open no call reaches the store and the local
//! limiter decides. When the duration has passed, exactly one probe call is let through; a probe
//! that succeeds closes the breaker, one that fails opens it again for another full duration.
//!
//! The breaker is a plain state machine over [`BootInstant`]s the caller supplies, so the
//! application, the integration tests and the unit tests drive it alike. A probe whose result
//! never arrives (the request was cancelled) is replaced by a new probe one open duration later.

use std::time::Duration;

use crate::value_object::boot_instant::BootInstant;

/// How many consecutive failures or timeouts open the breaker.
pub const BREAKER_FAILURE_THRESHOLD: u32 = 5;

/// What the breaker allows for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerPermit {
    /// The breaker is closed: the call goes to the store.
    Call,
    /// The breaker was open and its time has passed: this call is the one probe.
    Probe,
    /// The breaker is open, or a probe is in flight: the local limiter decides.
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    Closed { failures: u32 },
    Open { until: BootInstant },
    Probing { until: BootInstant },
}

/// The failure counter and the open interval of the shared store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreBreaker {
    open_duration: Duration,
    state: BreakerState,
}

impl StoreBreaker {
    /// A closed breaker that opens for `open_duration`.
    #[must_use]
    pub const fn new(open_duration: Duration) -> Self {
        Self {
            open_duration,
            state: BreakerState::Closed { failures: 0 },
        }
    }

    /// Asks whether a call may go to the store at `now`. A [`BreakerPermit::Probe`] answer starts
    /// the probe: later asks are skipped until its result is recorded or one open duration passes.
    pub fn permit(&mut self, now: BootInstant) -> BreakerPermit {
        match self.state {
            BreakerState::Closed { .. } => BreakerPermit::Call,
            BreakerState::Open { until } | BreakerState::Probing { until } if now < until => {
                BreakerPermit::Skip
            }
            BreakerState::Open { .. } | BreakerState::Probing { .. } => {
                self.state = BreakerState::Probing {
                    until: self.deadline(now),
                };
                BreakerPermit::Probe
            }
        }
    }

    /// Records that the call ended with an answer. A probe closes the breaker; a call of the
    /// closed breaker clears the failure count; a late call of an open breaker changes nothing.
    pub const fn record_success(&mut self, permit: BreakerPermit) {
        let closes = match permit {
            BreakerPermit::Probe => true,
            BreakerPermit::Call => matches!(self.state, BreakerState::Closed { .. }),
            BreakerPermit::Skip => false,
        };
        if closes {
            self.state = BreakerState::Closed { failures: 0 };
        }
    }

    /// Records that the call failed or timed out at `now`; `true` when this failure opened the
    /// breaker.
    pub fn record_failure(&mut self, permit: BreakerPermit, now: BootInstant) -> bool {
        match (permit, self.state) {
            (BreakerPermit::Probe, _) => {
                self.open(now);
                true
            }
            (BreakerPermit::Call, BreakerState::Closed { failures }) => {
                let failures = failures.saturating_add(1);
                if failures < BREAKER_FAILURE_THRESHOLD {
                    self.state = BreakerState::Closed { failures };
                    return false;
                }
                self.open(now);
                true
            }
            _ => false,
        }
    }

    fn open(&mut self, now: BootInstant) {
        self.state = BreakerState::Open {
            until: self.deadline(now),
        };
    }

    fn deadline(&self, now: BootInstant) -> BootInstant {
        now.checked_add(self.open_duration)
            .unwrap_or(BootInstant::from_elapsed(Duration::MAX))
    }
}

#[cfg(test)]
mod tests;
