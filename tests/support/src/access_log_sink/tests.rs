use std::time::SystemTime;

use iam_domain::{
    AccessAggregate, AccessClass, AccessDecision, AccessEntry, AccessLane, AccessLogSink as _,
    AccessRecord, DecisionReason,
};
use shared_domain::Uuid;

use super::RecordingAccessLogSink;

fn record() -> AccessRecord {
    AccessRecord {
        decision_id: Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH,
        method: "GET".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: None,
        route_template: None,
        status: 200,
        upstream: None,
        latency_us: 1,
        bytes_in: 0,
        bytes_out: 0,
        request_id: None,
        subject_id: None,
        subject_kind: None,
        decision: AccessDecision::Allow,
        reason: DecisionReason::Allowed,
        permission_key: None,
        denied: Vec::new(),
        project_id: None,
        policy_version: None,
        credential_digest_prefix: None,
    }
}

#[test]
fn the_sink_remembers_records_and_aggregates_by_lane_in_order() {
    let sink = RecordingAccessLogSink::new();
    let aggregate = AccessAggregate {
        lane: AccessLane::Audit,
        class: AccessClass::Audit,
        window_start: SystemTime::UNIX_EPOCH,
        route_id: None,
        route_template: None,
        status: 503,
        reason: DecisionReason::Unavailable,
        count: 4,
    };

    sink.write(AccessLane::Access, &AccessEntry::Record(Box::new(record())));
    sink.write(
        AccessLane::Audit,
        &AccessEntry::Aggregate(aggregate.clone()),
    );
    sink.write(AccessLane::Audit, &AccessEntry::Record(Box::new(record())));

    assert_eq!(sink.entries().len(), 3);
    assert_eq!(sink.records(AccessLane::Access).len(), 1);
    assert_eq!(sink.records(AccessLane::Audit).len(), 1);
    assert_eq!(sink.aggregates(), vec![aggregate]);
}

#[test]
fn a_withholding_sink_reports_only_the_acknowledgements_the_test_gives() {
    let sink = RecordingAccessLogSink::withholding();
    assert_eq!(sink.acknowledged_audit(), Some(0));

    sink.acknowledge(3);

    assert_eq!(sink.acknowledged_audit(), Some(3));
}

#[test]
fn a_plain_sink_keeps_no_account_of_acknowledgements() {
    let sink = RecordingAccessLogSink::new();

    sink.acknowledge(3);

    assert_eq!(sink.acknowledged_audit(), None);
}
