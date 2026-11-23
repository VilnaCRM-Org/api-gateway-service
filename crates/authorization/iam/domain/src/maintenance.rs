//! What the periodic maintenance removes, and when a record is old enough to go (FR-38, FR-52).
//!
//! Session revocations and cut-offs are not here: they leave only through the tombstones of
//! Story 13.6.

use std::time::{Duration, SystemTime};

use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;

/// How long idempotency records and change receipts are kept: 24 hours.
pub const RECORD_RETENTION: Duration = Duration::from_hours(24);

/// How long the ids of consumed User service events are kept: 7 days.
pub const INBOUND_EVENT_RETENTION: Duration = Duration::from_hours(168);

/// The largest number of orphaned grants that one run of the maintenance purges; the others go
/// with the next run.
pub const MAX_PURGED_GRANTS_PER_RUN: u32 = 1_000;

/// The instants before which a record is old enough to be removed: a record is removed when it is
/// strictly older than its cut-off, so a record exactly at the cut-off stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionCutoffs {
    /// Orphaned grants with `orphaned_at` before this instant are purged.
    pub orphaned_grants: SystemTime,
    /// Idempotency records created before this instant are removed.
    pub idempotency_records: SystemTime,
    /// Change receipts created before this instant are removed.
    pub change_receipts: SystemTime,
    /// Inbound-event ids processed before this instant are removed.
    pub inbound_events: SystemTime,
}

impl RetentionCutoffs {
    /// The cut-offs at `now`, with orphaned grants kept for `orphaned_grant_retention`. A
    /// retention longer than the time since 1970 puts the cut-off at 1970, so nothing is old
    /// enough.
    #[must_use]
    pub fn at(now: SystemTime, orphaned_grant_retention: Duration) -> Self {
        // `SystemTime` reaches before 1970 on some platforms, so the subtraction alone does not
        // stop at 1970.
        let before = |retention: Duration| {
            now.checked_sub(retention)
                .map_or(SystemTime::UNIX_EPOCH, |cutoff| {
                    cutoff.max(SystemTime::UNIX_EPOCH)
                })
        };
        Self {
            orphaned_grants: before(orphaned_grant_retention),
            idempotency_records: before(RECORD_RETENTION),
            change_receipts: before(RECORD_RETENTION),
            inbound_events: before(INBOUND_EVENT_RETENTION),
        }
    }
}

/// How many records of each kind a purge removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgedRecords {
    /// The idempotency records that were removed.
    pub idempotency_records: u64,
    /// The change receipts that were removed.
    pub change_receipts: u64,
    /// The inbound-event ids that were removed.
    pub inbound_events: u64,
}

impl PurgedRecords {
    /// The number of records of every kind.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.idempotency_records
            .saturating_add(self.change_receipts)
            .saturating_add(self.inbound_events)
    }
}

/// A grant that was orphaned long enough ago to be purged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredOrphanedGrant {
    /// The role that holds the grant.
    pub role_id: RoleId,
    /// The grant, an exact catalogue key.
    pub grant: PermissionGrant,
    /// When the grant was orphaned.
    pub orphaned_at: SystemTime,
}

#[cfg(test)]
mod tests;
