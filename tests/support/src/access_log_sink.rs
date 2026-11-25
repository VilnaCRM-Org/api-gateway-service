//! Access log sink double.

use std::sync::{Mutex, PoisonError};

use iam_domain::{AccessAggregate, AccessEntry, AccessLane, AccessLogSink, AccessRecord};

/// Remembers every entry it is asked to write, with its lane, in order.
#[derive(Debug, Default)]
pub struct RecordingAccessLogSink(Mutex<Vec<(AccessLane, AccessEntry)>>);

impl RecordingAccessLogSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every entry written so far, with its lane.
    #[must_use]
    pub fn entries(&self) -> Vec<(AccessLane, AccessEntry)> {
        self.0
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
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((lane, entry.clone()));
    }
}

#[cfg(test)]
mod tests;
