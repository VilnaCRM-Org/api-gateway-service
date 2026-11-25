//! `OutlierRule` and `EndpointHealth`: passive ejection of failing endpoints (FR-66).

/// How long an endpoint stays ejected when the configuration says nothing: 10 seconds.
pub const DEFAULT_EJECTION_MS: u64 = 10_000;

/// The largest share of an upstream's endpoints that is ejected at once, in percent.
pub const DEFAULT_MAX_EJECTION_PERCENT: u8 = 50;

/// The consecutive failures after which an endpoint is ejected when the upstream sets none.
pub const DEFAULT_CONSECUTIVE_ERRORS: u32 = 5;

/// When an endpoint is ejected, for how long and how many endpoints may be ejected at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutlierRule {
    consecutive_errors: u32,
    ejection_ms: u64,
    max_ejection_percent: u8,
}

impl OutlierRule {
    /// A rule that ejects after `consecutive_errors` failures in a row (at least 1), for
    /// `ejection_ms`, and never ejects more than `max_ejection_percent` of the endpoints.
    #[must_use]
    pub fn new(consecutive_errors: u32, ejection_ms: u64, max_ejection_percent: u8) -> Self {
        Self {
            consecutive_errors: consecutive_errors.max(1),
            ejection_ms,
            max_ejection_percent: max_ejection_percent.min(100),
        }
    }

    /// The rule of an upstream with `consecutive_errors` and the default ejection time and cap.
    #[must_use]
    pub fn for_threshold(consecutive_errors: u32) -> Self {
        Self::new(
            consecutive_errors,
            DEFAULT_EJECTION_MS,
            DEFAULT_MAX_EJECTION_PERCENT,
        )
    }

    /// How long an ejected endpoint is left out, in milliseconds.
    #[must_use]
    pub const fn ejection_ms(&self) -> u64 {
        self.ejection_ms
    }

    /// Whether `consecutive_errors` failures in a row call for an ejection.
    #[must_use]
    pub const fn trips(&self, consecutive_errors: u32) -> bool {
        consecutive_errors >= self.consecutive_errors
    }

    /// Whether one more endpoint may be ejected when `ejected` of `total` already are: the share
    /// after the ejection must not exceed the cap, so a lone endpoint is never ejected.
    #[must_use]
    pub fn may_eject(&self, ejected: usize, total: usize) -> bool {
        let after = u64::try_from(ejected.saturating_add(1)).unwrap_or(u64::MAX);
        let all = u64::try_from(total).unwrap_or(u64::MAX);
        after.saturating_mul(100) <= all.saturating_mul(u64::from(self.max_ejection_percent))
    }
}

/// What the gateway knows about the recent answers of one endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointHealth {
    consecutive_errors: u32,
    ejected_until_ms: Option<u64>,
}

impl EndpointHealth {
    /// Whether the endpoint is ejected at `now_ms`.
    #[must_use]
    pub fn is_ejected(&self, now_ms: u64) -> bool {
        self.ejected_until_ms.is_some_and(|until| now_ms < until)
    }

    /// The failures in a row.
    #[must_use]
    pub const fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors
    }

    /// Counts a good answer, which ends the run of failures.
    pub const fn record_success(&mut self) {
        self.consecutive_errors = 0;
    }

    /// Counts a failure at `now_ms` (a connect error or a 5xx response) and ejects the endpoint
    /// when `rule` trips and `may_eject` says the cap allows it; returns whether it was ejected
    /// by this call. An endpoint whose ejection has run out starts a new count.
    pub fn record_error(&mut self, rule: &OutlierRule, now_ms: u64, may_eject: bool) -> bool {
        if self.ejected_until_ms.is_some_and(|until| now_ms >= until) {
            *self = Self::default();
        }
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        let eject = may_eject && !self.is_ejected(now_ms) && rule.trips(self.consecutive_errors);
        if eject {
            self.ejected_until_ms = Some(now_ms.saturating_add(rule.ejection_ms()));
            self.consecutive_errors = 0;
        }
        eject
    }
}

#[cfg(test)]
mod tests;
