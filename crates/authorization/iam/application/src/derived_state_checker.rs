//! The `DerivedStateChecker` of the gateway (FR-74).
//!
//! Every check interval it asks the apply thread's state to rebuild the derived structures of one
//! group of shards, a sixteenth of them, and to compare them with the incremental ones; sixteen
//! intervals cover every shard once. The checker keeps the rotation and the interval, measured on
//! the boot clock, and it stops after a mismatch until the pod has rebootstrapped: the state is
//! wrong, so nothing more is judged on it.

use std::time::Duration;

use iam_domain::{BootInstant, CHECK_GROUPS, DerivedMismatch, DerivedStateAudit};

/// What one call of [`DerivedStateChecker::run`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// No check was due, or the checker waits for the rebootstrap after a mismatch.
    NotDue,
    /// A group was checked and its structures match the raw records.
    Passed {
        /// The group, `0..16`.
        group: usize,
        /// How many shards the check covered.
        shards: usize,
    },
    /// A structure differs from the raw records: the published snapshot is wrong.
    Mismatch(DerivedMismatch),
}

/// The rotation of the derived-state checks.
#[derive(Debug, Clone)]
pub struct DerivedStateChecker {
    interval: Duration,
    group: usize,
    last: Option<BootInstant>,
    stopped: bool,
}

impl DerivedStateChecker {
    /// A checker that runs one check per `interval` (`DERIVED_STATE_CHECK_INTERVAL`).
    #[must_use]
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            group: 0,
            last: None,
            stopped: false,
        }
    }

    /// Starts the checks again after the pod rebootstrapped: the first interval is counted from the
    /// next call of [`run`](Self::run).
    pub const fn restart(&mut self) {
        self.last = None;
        self.stopped = false;
    }

    /// Runs the check that is due at `now`, if any, against `audit`.
    pub fn run(&mut self, now: BootInstant, audit: &mut dyn DerivedStateAudit) -> CheckOutcome {
        if self.stopped || !self.due(now) {
            return CheckOutcome::NotDue;
        }
        self.last = Some(now);
        let group = self.group;
        self.group = group
            .saturating_add(1)
            .checked_rem(CHECK_GROUPS)
            .unwrap_or_default();
        match audit.audit_group(group) {
            Ok(shards) => CheckOutcome::Passed { group, shards },
            Err(mismatch) => {
                self.stopped = true;
                CheckOutcome::Mismatch(mismatch)
            }
        }
    }

    /// Whether the interval since the last check has passed; the first call only starts counting.
    fn due(&mut self, now: BootInstant) -> bool {
        let Some(last) = self.last else {
            self.last = Some(now);
            return false;
        };
        now.saturating_since(last) >= self.interval
    }
}

#[cfg(test)]
mod tests;
