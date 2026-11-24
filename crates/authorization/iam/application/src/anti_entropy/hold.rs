//! The hold that a topic ahead of PostgreSQL puts on the relay, and the counter of repairs.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Set while the state topic is ahead of PostgreSQL.
///
/// The relay publishes nothing while it is set, so no record is appended to a log that already
/// diverged.
#[derive(Debug, Default)]
pub struct TopicAheadHold(AtomicBool);

impl TopicAheadHold {
    /// A hold that is not set.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Sets or releases the hold.
    pub fn set(&self, held: bool) {
        self.0.store(held, Ordering::SeqCst);
    }

    /// Whether the relay must hold back.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// `anti_entropy_repairs_total`: the republished records and the alerts raised.
#[derive(Debug, Default)]
pub struct AntiEntropyCounters(AtomicU64);

impl AntiEntropyCounters {
    /// A counter at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Counts one repair or one alert.
    pub fn record(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    /// The value of `anti_entropy_repairs_total`.
    #[must_use]
    pub fn repairs_total(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
