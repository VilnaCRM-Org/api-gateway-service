//! The generic cell rate algorithm (GCRA) of a rate policy and the conservative limit of the
//! fallback (FR-65).
//!
//! The rule is pure: the theoretical arrival time of the key and the current instant are inputs, so
//! the Valkey script, the local limiter and the tests decide alike. A request is admitted while the
//! theoretical arrival time lies at most one burst tolerance ahead of now; an admitted request moves
//! it one emission interval further, a rejected one leaves it where it was.
//!
//! The emission interval is the period divided by the limit, rounded up to a whole nanosecond, so
//! in any window of one period (half open) at most `limit + burst` requests are admitted.

use std::time::Duration;

use super::decision::RateDecision;
use crate::rate_policy::fields::{RateFallback, RatePolicyFields};
use crate::value_object::boot_instant::BootInstant;

/// The decision and the theoretical arrival time that follows from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateOutcome {
    /// Whether the request passes.
    pub decision: RateDecision,
    /// The theoretical arrival time to keep for the key.
    pub theoretical_arrival: BootInstant,
}

/// GCRA over a theoretical arrival time with a limit, a period and a burst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecisionRule {
    emission_interval: Duration,
    tolerance: Duration,
}

impl RateDecisionRule {
    /// The theoretical arrival time of a key that has not been seen: it never lies ahead of now.
    pub const UNSEEN: BootInstant = BootInstant::from_elapsed(Duration::ZERO);

    /// The rule for `limit` requests per `period` with `burst` requests above the steady rate; a
    /// limit of 0 is read as 1.
    #[must_use]
    pub fn new(limit: u32, period: Duration, burst: u32) -> Self {
        let interval = period.as_nanos().div_ceil(u128::from(limit.max(1))).max(1);
        let emission_interval = u64::try_from(interval).map_or(Duration::MAX, Duration::from_nanos);
        Self {
            emission_interval,
            tolerance: emission_interval.saturating_mul(burst),
        }
    }

    /// The rule of the policy as configured.
    #[must_use]
    pub fn for_policy(fields: &RatePolicyFields) -> Self {
        Self::new(fields.limit(), period_of(fields), fields.burst())
    }

    /// The rule of one gateway pod while the shared counter is unavailable: the limit becomes
    /// [`Self::conservative_limit`] and the period and the burst stay.
    #[must_use]
    pub fn conservative(fields: &RatePolicyFields, ready_endpoints: u32) -> Self {
        let limit = Self::conservative_limit(fields.limit(), fields.fallback(), ready_endpoints);
        Self::new(limit, period_of(fields), fields.burst())
    }

    /// The limit of one pod: `limit / N_ready` for `divided` (at least 1, `N_ready` read as 1 when
    /// it is 0), the full limit for `full`.
    #[must_use]
    pub fn conservative_limit(limit: u32, fallback: RateFallback, ready_endpoints: u32) -> u32 {
        match fallback {
            RateFallback::Divided => limit
                .checked_div(ready_endpoints.max(1))
                .unwrap_or(limit)
                .max(1),
            RateFallback::Full => limit,
        }
    }

    /// The time between two requests at the steady rate.
    #[must_use]
    pub const fn emission_interval(&self) -> Duration {
        self.emission_interval
    }

    /// How far ahead of now the theoretical arrival time may lie for a request to be admitted.
    #[must_use]
    pub const fn tolerance(&self) -> Duration {
        self.tolerance
    }

    /// Decides the request that arrives at `now` for a key whose theoretical arrival time is
    /// `theoretical_arrival`.
    #[must_use]
    pub fn decide(&self, theoretical_arrival: BootInstant, now: BootInstant) -> RateOutcome {
        let ahead = theoretical_arrival.saturating_since(now);
        if ahead > self.tolerance {
            return RateOutcome {
                decision: RateDecision::Reject {
                    retry_after: ahead.saturating_sub(self.tolerance),
                },
                theoretical_arrival,
            };
        }
        let next = theoretical_arrival
            .max(now)
            .checked_add(self.emission_interval)
            .unwrap_or(BootInstant::from_elapsed(Duration::MAX));
        RateOutcome {
            decision: RateDecision::Admit,
            theoretical_arrival: next,
        }
    }
}

/// The period of the policy.
fn period_of(fields: &RatePolicyFields) -> Duration {
    Duration::from_secs(u64::from(fields.period_seconds()))
}

#[cfg(test)]
mod tests;
