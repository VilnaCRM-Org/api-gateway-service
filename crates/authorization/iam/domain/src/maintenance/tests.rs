use std::time::{Duration, SystemTime};

use super::{
    INBOUND_EVENT_RETENTION, MAX_PURGED_GRANTS_PER_RUN, PurgedRecords, RECORD_RETENTION,
    RetentionCutoffs,
};

fn at(hours: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(hours))
        .unwrap()
}

#[test]
fn the_retentions_are_one_day_for_records_and_a_week_for_event_ids() {
    assert_eq!(RECORD_RETENTION, Duration::from_hours(24));
    assert_eq!(INBOUND_EVENT_RETENTION, Duration::from_hours(168));
    assert_eq!(MAX_PURGED_GRANTS_PER_RUN, 1_000);
}

#[test]
fn the_cutoffs_lie_one_retention_before_now() {
    let now = at(1_000);

    let cutoffs = RetentionCutoffs::at(now, Duration::from_hours(48));

    assert_eq!(cutoffs.orphaned_grants, at(952));
    assert_eq!(cutoffs.idempotency_records, at(976));
    assert_eq!(cutoffs.change_receipts, at(976));
    assert_eq!(cutoffs.inbound_events, at(832));
}

#[test]
fn a_retention_longer_than_the_time_since_1970_puts_the_cutoff_at_1970() {
    let cutoffs = RetentionCutoffs::at(at(10), Duration::from_hours(48));

    assert_eq!(cutoffs.orphaned_grants, SystemTime::UNIX_EPOCH);
    assert_eq!(cutoffs.idempotency_records, SystemTime::UNIX_EPOCH);
    assert_eq!(cutoffs.change_receipts, SystemTime::UNIX_EPOCH);
    assert_eq!(cutoffs.inbound_events, SystemTime::UNIX_EPOCH);
}

#[test]
fn the_total_adds_every_kind_and_saturates() {
    let purged = PurgedRecords {
        idempotency_records: 1,
        change_receipts: 2,
        inbound_events: 3,
    };
    let saturated = PurgedRecords {
        idempotency_records: u64::MAX,
        change_receipts: 1,
        inbound_events: 1,
    };

    assert_eq!(purged.total(), 6);
    assert_eq!(PurgedRecords::default().total(), 0);
    assert_eq!(saturated.total(), u64::MAX);
}
