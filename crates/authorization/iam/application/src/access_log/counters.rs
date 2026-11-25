//! The counters of the access log.

use std::sync::atomic::{AtomicU64, Ordering};

use iam_domain::{AccessClass, AccessLane};

/// The records that never reached a sink, by lane and class (`access_log_dropped_total`).
#[derive(Debug, Default)]
pub struct AccessLogCounters {
    dropped: [AtomicU64; SLOTS],
}

/// Two lanes times three classes.
const SLOTS: usize = 6;

impl AccessLogCounters {
    /// Counters that all read zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts one dropped record and emits the metric event `access_log_dropped_total`.
    pub fn dropped(&self, lane: AccessLane, class: AccessClass) {
        if let Some(counter) = self.dropped.get(slot(lane, class)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        emit_dropped(lane, class);
    }

    /// How many records of `lane` and `class` were dropped.
    #[must_use]
    pub fn dropped_count(&self, lane: AccessLane, class: AccessClass) -> u64 {
        self.dropped
            .get(slot(lane, class))
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }
}

fn emit_dropped(lane: AccessLane, class: AccessClass) {
    let lane = lane.as_str();
    let class = class.as_str();
    tracing::warn!(
        target: "metrics",
        metric = "access_log_dropped_total",
        lane,
        class,
        value = 1_u64,
    );
}

const fn slot(lane: AccessLane, class: AccessClass) -> usize {
    match (lane, class) {
        (AccessLane::Access, AccessClass::Allow) => 0,
        (AccessLane::Access, AccessClass::Error) => 1,
        (AccessLane::Access, AccessClass::Audit) => 2,
        (AccessLane::Audit, AccessClass::Allow) => 3,
        (AccessLane::Audit, AccessClass::Error) => 4,
        (AccessLane::Audit, AccessClass::Audit) => 5,
    }
}

#[cfg(test)]
mod tests;
