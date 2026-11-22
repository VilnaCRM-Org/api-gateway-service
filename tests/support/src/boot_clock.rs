//! Boot clock double.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{BootClock, BootInstant};

/// A boot clock that moves only when the test advances it, by small steps or by one jump (such as
/// a host suspend). Elapsed time never decreases.
#[derive(Debug, Default)]
pub struct FakeBootClock(Mutex<Duration>);

impl FakeBootClock {
    /// A clock at boot (zero elapsed time).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A clock at `instant`.
    #[must_use]
    pub const fn starting_at(instant: BootInstant) -> Self {
        Self(Mutex::new(instant.elapsed()))
    }

    /// Moves the clock forward by `step`, saturating at the largest duration.
    pub fn advance(&self, step: Duration) {
        let mut elapsed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *elapsed = elapsed.saturating_add(step);
    }

    /// Moves the clock forward by `gap` at once, as a suspend of the host does.
    pub fn jump(&self, gap: Duration) {
        self.advance(gap);
    }
}

impl BootClock for FakeBootClock {
    fn now(&self) -> BootInstant {
        BootInstant::from_elapsed(*self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests;
