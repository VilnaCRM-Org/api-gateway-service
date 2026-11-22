//! Boot clock port.

use crate::value_object::boot_instant::BootInstant;

/// Source of elapsed time on `CLOCK_BOOTTIME`.
///
/// It counts suspend time, never goes backwards and is never compared across hosts. It times
/// freshness, watchdog gaps, breakers and timers; wall clock timestamps come from the `Clock` port.
pub trait BootClock: std::fmt::Debug + Send + Sync {
    /// The current instant.
    fn now(&self) -> BootInstant;
}
