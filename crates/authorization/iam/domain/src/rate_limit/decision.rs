//! The outcome of one rate-limit check.

use std::time::Duration;

/// Whether a request may pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The request is within the limit.
    Admit,
    /// The request is over the limit and may be retried after `retry_after`.
    Reject {
        /// The time until the rule would admit the request.
        retry_after: Duration,
    },
}

impl RateDecision {
    /// Whether the request passes.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admit)
    }

    /// The time until a rejected request would be admitted, `None` for an admitted one.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::Admit => None,
            Self::Reject { retry_after } => Some(retry_after),
        }
    }

    /// The value of the `Retry-After` header: whole seconds, rounded up and at least 1, `None` for
    /// an admitted request.
    #[must_use]
    pub fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after().map(|wait| {
            wait.as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0))
                .max(1)
        })
    }
}

#[cfg(test)]
mod tests;
