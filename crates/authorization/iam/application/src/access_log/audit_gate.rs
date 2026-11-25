//! The state of the audit lane that the request path reads (Story 14.2, FR-50, NFR-24).
//!
//! An operation on an always-audit or sensitive key may only run while its audit record has a
//! place to go: the writer publishes how many audit entries the log store has not acknowledged and
//! since when the oldest of them waits, the channel marks itself full when it drops an audit
//! record, and [`AuditGate::admits`] turns those three facts into the answer of audit-or-deny.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use shared_domain::Clock;

/// The stored form of "no entry waits".
const NONE: u64 = u64::MAX;

/// The audit lane as the request path sees it.
#[derive(Debug)]
pub struct AuditGate {
    clock: Arc<dyn Clock>,
    max_pending: Duration,
    capacity: u64,
    pending: AtomicU64,
    oldest_micros: AtomicU64,
    channel_full: AtomicBool,
}

impl AuditGate {
    /// A gate that refuses once the oldest unacknowledged entry has waited longer than
    /// `max_pending` on `clock`, or `capacity` entries wait.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, max_pending: Duration, capacity: usize) -> Self {
        Self {
            clock,
            max_pending,
            capacity: u64::try_from(capacity).unwrap_or(u64::MAX),
            pending: AtomicU64::new(0),
            oldest_micros: AtomicU64::new(NONE),
            channel_full: AtomicBool::new(false),
        }
    }

    /// Whether an operation that needs an audit record may run now: the lane is not full and its
    /// oldest unacknowledged entry has not waited longer than the bound.
    #[must_use]
    pub fn admits(&self) -> bool {
        !self.channel_full.load(Ordering::Acquire)
            && self.pending() < self.capacity
            && self.oldest_wait() <= self.max_pending
    }

    /// How many audit entries the log store has not acknowledged.
    #[must_use]
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    /// How long the oldest unacknowledged entry has waited; zero when none waits.
    #[must_use]
    pub fn oldest_wait(&self) -> Duration {
        let oldest = self.oldest_micros.load(Ordering::Acquire);
        if oldest == NONE {
            return Duration::ZERO;
        }
        let waiting_since = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(oldest))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.clock
            .now()
            .duration_since(waiting_since)
            .unwrap_or(Duration::ZERO)
    }

    /// Notes that the channel dropped an audit record because it was full.
    pub fn mark_channel_full(&self) {
        self.channel_full.store(true, Ordering::Release);
    }

    /// Notes that the writer took a record from the channel, which has room again.
    pub fn clear_channel_full(&self) {
        self.channel_full.store(false, Ordering::Release);
    }

    /// Publishes the account of the writer: how many entries wait for an acknowledgement and
    /// since when the oldest waits.
    pub fn publish(&self, pending: u64, oldest: Option<SystemTime>) {
        let micros = oldest.map_or(NONE, unix_micros);
        self.oldest_micros.store(micros, Ordering::Release);
        self.pending.store(pending, Ordering::Release);
    }

    /// The most audit entries that may wait for an acknowledgement.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }
}

/// The microseconds since the Unix epoch; zero before it.
fn unix_micros(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_micros()).ok())
        .map_or(0, |micros| micros.min(NONE.saturating_sub(1)))
}

#[cfg(test)]
mod tests;
