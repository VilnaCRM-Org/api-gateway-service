use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AccessAggregate, AccessClass, AccessEntry, AccessLane, AccessLogSink as _, DecisionReason,
};
use test_support::access_log_sink::RecordingAccessLogSink;

use super::LaneSplitSink;

fn aggregate(lane: AccessLane) -> AccessEntry {
    AccessEntry::Aggregate(AccessAggregate {
        lane,
        class: AccessClass::Audit,
        window_start: SystemTime::UNIX_EPOCH,
        route_id: None,
        route_template: None,
        status: 403,
        reason: DecisionReason::PermissionMissing,
        count: 1,
    })
}

#[test]
fn each_lane_reaches_its_own_sink_and_only_it() {
    let access = Arc::new(RecordingAccessLogSink::new());
    let audit = Arc::new(RecordingAccessLogSink::new());
    let split = LaneSplitSink::new(
        Arc::<RecordingAccessLogSink>::clone(&access),
        Arc::<RecordingAccessLogSink>::clone(&audit),
    );

    split.write(AccessLane::Access, &aggregate(AccessLane::Access));
    split.write(AccessLane::Audit, &aggregate(AccessLane::Audit));
    split.write(AccessLane::Audit, &aggregate(AccessLane::Audit));

    assert_eq!(access.entries().len(), 1);
    assert_eq!(audit.entries().len(), 2);
    assert!(
        access
            .entries()
            .iter()
            .all(|(lane, _)| *lane == AccessLane::Access)
    );
}

#[test]
fn the_audit_account_is_the_account_of_the_audit_sink() {
    let access = Arc::new(RecordingAccessLogSink::withholding());
    let audit = Arc::new(RecordingAccessLogSink::withholding());
    let split = LaneSplitSink::new(
        Arc::<RecordingAccessLogSink>::clone(&access),
        Arc::<RecordingAccessLogSink>::clone(&audit),
    );

    access.acknowledge(5);
    audit.acknowledge(2);

    assert_eq!(split.acknowledged_audit(), Some(2));
    split.flush();
}
