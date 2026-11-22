//! Times kept in whole microseconds since 1970, the precision of the store.

use std::time::{Duration, SystemTime};

/// Whole microseconds since 1970, or nothing when the time lies before 1970 or past the largest
/// number of microseconds in 64 bits.
pub(crate) fn since_epoch(time: SystemTime) -> Option<i64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
}

/// The time `micros` microseconds after 1970, or nothing when `micros` is negative.
pub(crate) fn time_of(micros: i64) -> Option<SystemTime> {
    u64::try_from(micros)
        .ok()
        .and_then(|micros| SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros)))
}

#[cfg(test)]
mod tests;
