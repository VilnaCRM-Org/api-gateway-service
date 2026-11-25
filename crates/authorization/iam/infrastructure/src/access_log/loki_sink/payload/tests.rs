use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessAggregate, AccessClass, AccessDecision, AccessEntry, AccessLane, AccessRecord,
    DecisionReason, SubjectKind,
};
use serde_json::Value;
use shared_domain::Uuid;

use super::{pending_of, push_body};

fn uuid(counter: u32) -> Uuid {
    Uuid::parse(&format!("00000000-0000-7000-8000-{counter:012x}")).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn record(counter: u32, seconds: u64) -> AccessRecord {
    AccessRecord {
        decision_id: uuid(counter),
        occurred_at: at(seconds),
        method: "DELETE".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: Some(uuid(2)),
        route_template: Some("/api/orders/{id}".to_owned()),
        status: 403,
        upstream: Some("orders".to_owned()),
        latency_us: 750,
        bytes_in: 10,
        bytes_out: 20,
        request_id: Some("req-9".to_owned()),
        subject_id: Some(uuid(3).to_string()),
        subject_kind: Some(SubjectKind::User),
        decision: AccessDecision::Deny,
        reason: DecisionReason::PermissionMissing,
        permission_key: None,
        denied: Vec::new(),
        project_id: None,
        policy_version: Some(42),
        credential_digest_prefix: None,
    }
}

fn entry(record: AccessRecord) -> AccessEntry {
    AccessEntry::Record(Box::new(record))
}

#[test]
fn a_record_has_the_labels_the_metadata_and_the_nanosecond_timestamp_of_loki() {
    let pending = pending_of(AccessLane::Audit, &entry(record(1, 1_800_000_000)));

    assert_eq!(pending.stream.lane, "audit");
    assert_eq!(pending.stream.decision, "deny");
    assert_eq!(pending.stream.upstream, "orders");
    assert_eq!(pending.timestamp_ns, 1_800_000_000_000_000_000);
    let names: Vec<&str> = pending.metadata.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "subject_id",
            "decision_id",
            "request_id",
            "route_id",
            "status",
            "reason",
            "policy_version",
            "subject_kind"
        ]
    );
    assert!(pending.metadata.contains(&("status", "403".to_owned())));
    assert!(
        pending
            .metadata
            .contains(&("subject_kind", "user".to_owned()))
    );
    assert!(pending.line.contains(&uuid(1).to_string()));
}

#[test]
fn a_field_the_record_lacks_is_left_out_and_a_missing_upstream_is_none() {
    let mut bare = record(1, 10);
    bare.upstream = None;
    bare.subject_id = None;
    bare.subject_kind = None;
    bare.request_id = None;
    bare.route_id = None;
    bare.policy_version = None;

    let pending = pending_of(AccessLane::Audit, &entry(bare));

    assert_eq!(pending.stream.upstream, "none");
    let names: Vec<&str> = pending.metadata.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["decision_id", "status", "reason"]);
}

#[test]
fn an_aggregate_is_pushed_as_an_aggregate_decision_with_its_window_start() {
    let aggregate = AccessAggregate {
        lane: AccessLane::Audit,
        class: AccessClass::Audit,
        window_start: at(1_800_000_001),
        route_id: Some(uuid(2)),
        route_template: Some("/api/orders/{id}".to_owned()),
        status: 403,
        reason: DecisionReason::PermissionMissing,
        count: 7,
    };

    let pending = pending_of(AccessLane::Audit, &AccessEntry::Aggregate(aggregate));

    assert_eq!(pending.stream.decision, "aggregate");
    assert_eq!(pending.stream.upstream, "none");
    assert_eq!(pending.timestamp_ns, 1_800_000_001_000_000_000);
    assert!(pending.line.contains("\"count\":7"));
    let names: Vec<&str> = pending.metadata.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["route_id", "status", "reason"]);
}

#[test]
fn the_body_has_one_stream_per_label_set_with_values_in_time_order_and_the_metadata_last() {
    let mut other = record(3, 1_800_000_005);
    other.upstream = Some("billing".to_owned());
    let lines = vec![
        pending_of(AccessLane::Audit, &entry(record(2, 1_800_000_009))),
        pending_of(AccessLane::Audit, &entry(record(1, 1_800_000_001))),
        pending_of(AccessLane::Audit, &entry(other)),
    ];

    let body: Value = serde_json::from_str(&push_body("gateway", "test", &lines)).unwrap();

    let streams = body["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 2);
    let orders = streams
        .iter()
        .find(|stream| stream["stream"]["upstream"] == "orders")
        .unwrap();
    assert_eq!(orders["stream"]["app"], "gateway");
    assert_eq!(orders["stream"]["env"], "test");
    assert_eq!(orders["stream"]["lane"], "audit");
    assert_eq!(orders["stream"]["decision"], "deny");
    let values = orders["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0][0], "1800000001000000000");
    assert_eq!(values[1][0], "1800000009000000000");
    assert_eq!(values[0][2]["decision_id"], uuid(1).to_string());
    assert_eq!(values[0][2]["status"], "403");
}

#[test]
fn the_size_of_a_line_counts_its_text_and_its_metadata() {
    let pending = pending_of(AccessLane::Audit, &entry(record(1, 10)));
    let metadata: usize = pending
        .metadata
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();

    assert_eq!(pending.size(), pending.line.len() + metadata);
}
