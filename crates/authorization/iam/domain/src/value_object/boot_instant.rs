//! An instant on the `BootClock`.

use std::time::Duration;

/// The time elapsed since the host booted, suspend time included. Instants of different hosts are
/// never compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootInstant(Duration);

impl BootInstant {
    /// The instant at `elapsed` after boot.
    #[must_use]
    pub const fn from_elapsed(elapsed: Duration) -> Self {
        Self(elapsed)
    }

    /// The time elapsed since boot.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.0
    }

    /// The time from `earlier` to this instant, zero when `earlier` is not earlier.
    #[must_use]
    pub const fn saturating_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// The instant `duration` later; `None` when it cannot be represented.
    #[must_use]
    pub const fn checked_add(self, duration: Duration) -> Option<Self> {
        match self.0.checked_add(duration) {
            Some(elapsed) => Some(Self(elapsed)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests;
