//! `LinuxBootClock`: `CLOCK_BOOTTIME` through `rustix`.

use std::time::Duration;

use iam_domain::{BootClock, BootInstant};
use rustix::time::{ClockId, clock_gettime};

/// Elapsed time since the host booted, suspend time included; it never goes backwards.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxBootClock;

impl BootClock for LinuxBootClock {
    fn now(&self) -> BootInstant {
        let spec = clock_gettime(ClockId::Boottime);
        let seconds = u64::try_from(spec.tv_sec).unwrap_or(0);
        let nanos = u32::try_from(spec.tv_nsec).unwrap_or(0);
        BootInstant::from_elapsed(Duration::new(seconds, nanos))
    }
}

#[cfg(test)]
mod tests;
