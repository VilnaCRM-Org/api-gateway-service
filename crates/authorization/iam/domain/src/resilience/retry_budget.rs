//! `RetryBudget`: how many retries an upstream can afford (FR-66).

/// The requests after which the counters are halved, so that the budget follows the recent
/// requests of the upstream and not its whole history.
pub const BUDGET_WINDOW_REQUESTS: u64 = 1_000;

/// The retries an upstream is always allowed within its window, so that a quiet upstream can
/// retry the odd refused connection although 10% of a handful of requests is below one.
pub const BUDGET_FLOOR_RETRIES: u64 = 1;

/// The share of an upstream's recent requests that may be retries.
///
/// A retry is allowed while the retries of the window stay below the budget percent of its
/// requests, and always while fewer than [`BUDGET_FLOOR_RETRIES`] were made. A budget of zero
/// allows none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryBudget {
    percent: u8,
    requests: u64,
    retries: u64,
}

impl RetryBudget {
    /// An empty budget of `percent` of the requests; a value above 100 counts as 100.
    #[must_use]
    pub fn new(percent: u8) -> Self {
        Self {
            percent: percent.min(100),
            requests: 0,
            retries: 0,
        }
    }

    /// Counts a request that was sent to the upstream.
    pub const fn record_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
        if self.requests > BUDGET_WINDOW_REQUESTS {
            self.requests = self.requests.saturating_div(2);
            self.retries = self.retries.saturating_div(2);
        }
    }

    /// The requests counted in the window.
    #[must_use]
    pub const fn requests(&self) -> u64 {
        self.requests
    }

    /// The retries counted in the window.
    #[must_use]
    pub const fn retries(&self) -> u64 {
        self.retries
    }

    /// Whether one more retry fits the budget.
    #[must_use]
    pub fn allows_retry(&self) -> bool {
        if self.percent == 0 {
            return false;
        }
        let share = self
            .requests
            .saturating_mul(u64::from(self.percent))
            .saturating_div(100);
        self.retries < share.max(BUDGET_FLOOR_RETRIES)
    }

    /// Spends one retry when the budget allows it; `false` when it does not.
    pub fn try_retry(&mut self) -> bool {
        let allowed = self.allows_retry();
        if allowed {
            self.retries = self.retries.saturating_add(1);
        }
        allowed
    }

    /// The same budget with another percent, as when the upstream is reconfigured; the counters
    /// stay.
    #[must_use]
    pub fn with_percent(self, percent: u8) -> Self {
        Self {
            percent: percent.min(100),
            ..self
        }
    }
}

#[cfg(test)]
mod tests;
