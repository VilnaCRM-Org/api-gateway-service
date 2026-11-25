//! Access log sink double.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use iam_domain::{AccessAggregate, AccessEntry, AccessLane, AccessLogSink, AccessRecord};

/// Remembers every entry it is asked to write, with its lane, in order.
///
/// A sink made with [`Self::withholding`] also keeps the account of audit acknowledgements, which
/// the test advances with [`Self::acknowledge`]; any other sink keeps none.
#[derive(Debug, Default)]
pub struct RecordingAccessLogSink {
    written: Mutex<Vec<(AccessLane, AccessEntry)>>,
    acknowledged: Option<AtomicU64>,
}

impl RecordingAccessLogSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty sink that acknowledges no audit entry until the test says so.
    #[must_use]
    pub const fn withholding() -> Self {
        Self {
            written: Mutex::new(Vec::new()),
            acknowledged: Some(AtomicU64::new(0)),
        }
    }

    /// Acknowledges `count` more audit entries, as the log store would; does nothing for a sink
    /// that keeps no account.
    pub fn acknowledge(&self, count: u64) {
        if let Some(acknowledged) = self.acknowledged.as_ref() {
            acknowledged.fetch_add(count, Ordering::AcqRel);
        }
    }

    /// Every entry written so far, with its lane.
    #[must_use]
    pub fn entries(&self) -> Vec<(AccessLane, AccessEntry)> {
        self.written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The records written to `lane`, in order; aggregates are left out.
    #[must_use]
    pub fn records(&self, lane: AccessLane) -> Vec<AccessRecord> {
        self.entries()
            .into_iter()
            .filter(|(written, _entry)| *written == lane)
            .filter_map(|(_lane, entry)| match entry {
                AccessEntry::Record(record) => Some(*record),
                AccessEntry::Aggregate(_aggregate) => None,
            })
            .collect()
    }

    /// The aggregates written so far, in order.
    #[must_use]
    pub fn aggregates(&self) -> Vec<AccessAggregate> {
        self.entries()
            .into_iter()
            .filter_map(|(_lane, entry)| match entry {
                AccessEntry::Aggregate(aggregate) => Some(aggregate),
                AccessEntry::Record(_record) => None,
            })
            .collect()
    }
}

impl AccessLogSink for RecordingAccessLogSink {
    fn write(&self, lane: AccessLane, entry: &AccessEntry) {
        self.written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((lane, entry.clone()));
    }

    fn acknowledged_audit(&self) -> Option<u64> {
        self.acknowledged
            .as_ref()
            .map(|acknowledged| acknowledged.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests;
