//! The two intervals of the anti-entropy task.

use std::time::Duration;

/// An interval of the anti-entropy task that the configuration refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAntiEntropySettings {
    /// `ANTI_ENTROPY_HEAD_INTERVAL` is zero.
    #[error("ANTI_ENTROPY_HEAD_INTERVAL must be longer than 0s")]
    HeadInterval,
    /// `ANTI_ENTROPY_FULL_INTERVAL` is zero or shorter than `ANTI_ENTROPY_HEAD_INTERVAL`.
    #[error(
        "ANTI_ENTROPY_FULL_INTERVAL must be longer than 0s and at least ANTI_ENTROPY_HEAD_INTERVAL"
    )]
    FullInterval,
}

/// The settings of the anti-entropy task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiEntropySettings {
    head_interval: Duration,
    full_interval: Duration,
}

impl AntiEntropySettings {
    /// The settings with `head_interval` between two head checks and `full_interval` between two
    /// shadow bootstraps.
    ///
    /// # Errors
    ///
    /// [`InvalidAntiEntropySettings::HeadInterval`] when the head interval is zero and
    /// [`InvalidAntiEntropySettings::FullInterval`] when the full interval is zero or shorter than
    /// the head interval.
    pub fn new(
        head_interval: Duration,
        full_interval: Duration,
    ) -> Result<Self, InvalidAntiEntropySettings> {
        if head_interval.is_zero() {
            return Err(InvalidAntiEntropySettings::HeadInterval);
        }
        if full_interval.is_zero() || full_interval < head_interval {
            return Err(InvalidAntiEntropySettings::FullInterval);
        }
        Ok(Self {
            head_interval,
            full_interval,
        })
    }

    /// `ANTI_ENTROPY_HEAD_INTERVAL`: how often the head check runs.
    #[must_use]
    pub const fn head_interval(self) -> Duration {
        self.head_interval
    }

    /// `ANTI_ENTROPY_FULL_INTERVAL`: how often the shadow bootstrap runs.
    #[must_use]
    pub const fn full_interval(self) -> Duration {
        self.full_interval
    }
}

impl Default for AntiEntropySettings {
    /// A head check every 5 seconds and a shadow bootstrap every 10 minutes.
    fn default() -> Self {
        Self {
            head_interval: Duration::from_secs(5),
            full_interval: Duration::from_mins(10),
        }
    }
}

#[cfg(test)]
mod tests;
