//! The proof that one probe of the state topic produced.

use std::time::Duration;

use crate::value_object::boot_instant::BootInstant;

/// What a successful probe shows: at `taken_at` the last stable offset of the state topic was
/// `watermark`, confirmed by a quorum of the replica brokers.
///
/// A snapshot that holds every complete version whose last record lies below `watermark` contains
/// every change acknowledged before `taken_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessProof {
    /// `t_s`: the instant on the boot clock, recorded before the probe sent its first request.
    pub taken_at: BootInstant,
    /// `HW(t_s)`: the last stable offset of the state partition.
    pub watermark: i64,
}

impl FreshnessProof {
    /// The age of the proof at `now`, zero when `now` is not after `taken_at`.
    #[must_use]
    pub const fn age(&self, now: BootInstant) -> Duration {
        now.saturating_since(self.taken_at)
    }
}

#[cfg(test)]
mod tests;
