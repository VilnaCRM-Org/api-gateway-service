//! Clock double.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use shared_domain::Clock;

/// Always returns the same time.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(SystemTime);

impl FixedClock {
    /// A clock fixed at `time`.
    #[must_use]
    pub const fn at(time: SystemTime) -> Self {
        Self(time)
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// A clock the test moves forward.
#[derive(Debug)]
pub struct ManualClock(Mutex<SystemTime>);

impl ManualClock {
    /// A clock that reads `time` until it is advanced.
    #[must_use]
    pub const fn at(time: SystemTime) -> Self {
        Self(Mutex::new(time))
    }

    /// Moves the clock forward by `by`; a time past the end of `SystemTime` keeps the clock where
    /// it is.
    pub fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(later) = now.checked_add(by) {
            *now = later;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
