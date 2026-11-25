use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessAggregate, AccessClass, AccessDecision, AccessEntry, AccessLane, AccessLogSink as _,
    AccessRecord, DecisionReason, SubjectKind,
};
use serde_json::Value;
use shared_domain::Uuid;

use super::{StdoutAccessLogSink, render_entry};

#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap()
    }
}

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Broken;

impl Write for Broken {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn uuid(counter: u32) -> Uuid {
    Uuid::parse(&format!("00000000-0000-7000-8000-{counter:012x}")).unwrap()
}

fn record() -> AccessRecord {
    AccessRecord {
        decision_id: uuid(1),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_800_000_000_123_456))
            .unwrap(),
        method: "GET".to_owned(),
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
        denied: vec!["rest:orders:GET /api/orders/{}".to_owned()],
        project_id: None,
        policy_version: Some(42),
        credential_digest_prefix: Some("0a1b2c3d".to_owned()),
    }
}

fn parsed(line: &str) -> Value {
    serde_json::from_str(line).unwrap()
}

#[test]
fn a_record_is_one_json_line_with_the_fields_of_the_access_record() {
    let line = render_entry(AccessLane::Audit, &AccessEntry::Record(Box::new(record())));
    let json = parsed(&line);

    assert!(!line.contains('\n'));
    assert_eq!(json["kind"], "record");
    assert_eq!(json["lane"], "audit");
    assert_eq!(json["decision_id"], uuid(1).to_string());
    assert_eq!(json["occurred_at"], 1_800_000_000_123_456_u64);
    assert_eq!(json["method"], "GET");
    assert_eq!(json["host"], "api.example.test");
    assert_eq!(json["route_id"], uuid(2).to_string());
    assert_eq!(json["route_template"], "/api/orders/{id}");
    assert_eq!(json["status"], 403);
    assert_eq!(json["upstream"], "orders");
    assert_eq!(json["latency_us"], 750);
    assert_eq!(json["bytes_in"], 10);
    assert_eq!(json["bytes_out"], 20);
    assert_eq!(json["request_id"], "req-9");
    assert_eq!(json["subject_kind"], "user");
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["reason"], "permission_missing");
    assert_eq!(json["permission_key"], Value::Null);
    assert_eq!(json["denied"][0], "rest:orders:GET /api/orders/{}");
    assert_eq!(json["project_id"], Value::Null);
    assert_eq!(json["policy_version"], 42);
    assert_eq!(json["credential_digest_prefix"], "0a1b2c3d");
}

#[test]
fn the_project_of_a_record_is_printed_as_its_uuid() {
    let mut with_project = record();
    with_project.project_id = Some(uuid(4));

    let line = render_entry(
        AccessLane::Access,
        &AccessEntry::Record(Box::new(with_project)),
    );

    assert_eq!(parsed(&line)["project_id"], uuid(4).to_string());
}

#[test]
fn an_aggregate_is_one_json_line_with_its_count() {
    let aggregate = AccessAggregate {
        lane: AccessLane::Access,
        class: AccessClass::Error,
        window_start: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(500_000))
            .unwrap(),
        route_id: Some(uuid(2)),
        route_template: Some("/api/orders/{id}".to_owned()),
        status: 503,
        reason: DecisionReason::Unavailable,
        count: 4_000,
    };

    let json = parsed(&render_entry(
        AccessLane::Access,
        &AccessEntry::Aggregate(aggregate),
    ));

    assert_eq!(json["kind"], "aggregate");
    assert_eq!(json["lane"], "access");
    assert_eq!(json["class"], "error");
    assert_eq!(json["occurred_at"], 1_800_000_000_000_000_u64);
    assert_eq!(json["status"], 503);
    assert_eq!(json["reason"], "unavailable");
    assert_eq!(json["count"], 4_000);
}

#[test]
fn the_sink_writes_one_line_per_entry_to_its_writer() {
    let buffer = Buffer::default();
    let sink = StdoutAccessLogSink::to_writer(buffer.clone());

    sink.write(AccessLane::Access, &AccessEntry::Record(Box::new(record())));
    sink.write(AccessLane::Audit, &AccessEntry::Record(Box::new(record())));

    let text = buffer.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(parsed(lines[0])["lane"], "access");
    assert_eq!(parsed(lines[1])["lane"], "audit");
    assert!(text.ends_with('\n'));
}

#[test]
fn a_writer_that_fails_loses_the_entry_without_panicking() {
    let sink = StdoutAccessLogSink::to_writer(Broken);

    sink.write(AccessLane::Audit, &AccessEntry::Record(Box::new(record())));
}

#[test]
fn the_default_sink_writes_to_the_process_output() {
    let sink = StdoutAccessLogSink::default();

    assert!(format!("{sink:?}").contains("StdoutAccessLogSink"));
}
