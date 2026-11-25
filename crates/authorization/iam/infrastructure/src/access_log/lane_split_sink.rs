//! The sink of production: the ordinary lane to one sink, the audit lane to another (Story 14.2).

use std::sync::Arc;

use iam_domain::{AccessEntry, AccessLane, AccessLogSink};

/// Writes the ordinary lane to `access` and the audit lane to `audit`, so that no audit-lane entry
/// reaches the sink of the ordinary lane (stdout in production).
///
/// The audit account of the sink is the account of `audit`.
#[derive(Debug)]
pub struct LaneSplitSink {
    access: Arc<dyn AccessLogSink>,
    audit: Arc<dyn AccessLogSink>,
}

impl LaneSplitSink {
    /// A sink that sends each lane to its own sink.
    #[must_use]
    pub fn new(access: Arc<dyn AccessLogSink>, audit: Arc<dyn AccessLogSink>) -> Self {
        Self { access, audit }
    }
}

impl AccessLogSink for LaneSplitSink {
    fn write(&self, lane: AccessLane, entry: &AccessEntry) {
        match lane {
            AccessLane::Access => self.access.write(lane, entry),
            AccessLane::Audit => self.audit.write(lane, entry),
        }
    }

    fn acknowledged_audit(&self) -> Option<u64> {
        self.audit.acknowledged_audit()
    }

    fn flush(&self) {
        self.access.flush();
        self.audit.flush();
    }
}

#[cfg(test)]
mod tests;
