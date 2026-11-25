use iam_domain::{
    AccessDecision, AccessLane, AccessLogQueryError, AccessRecord, DecisionReason, SubjectKind,
};
use serde_json::{Value, json};
use shared_domain::Uuid;
use std::time::{Duration, SystemTime};

use super::entries_of;
use crate::access_log::stdout_sink::render_entry;

fn record(n: u128) -> AccessRecord {
    AccessRecord {
        decision_id: Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{n:012x}")).unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_700_000_000_123_456))
            .unwrap(),
        method: "GET".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: Some(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-0000000000aa").unwrap()),
        route_template: Some("/api/users/{id}".to_owned()),
        status: 403,
        upstream: Some("user-service".to_owned()),
        latency_us: 1_200,
        bytes_in: 10,
        bytes_out: 64,
        request_id: Some("req-1".to_owned()),
        subject_id: Some("user-1".to_owned()),
        subject_kind: Some(SubjectKind::User),
        decision: AccessDecision::Deny,
        reason: DecisionReason::PermissionMissing,
        permission_key: Some("user:read".to_owned()),
        denied: vec!["user:read".to_owned()],
        project_id: None,
        policy_version: Some(7),
        credential_digest_prefix: Some("deadbeef".to_owned()),
    }
}

fn line_of(record: &AccessRecord) -> String {
    render_entry(
        AccessLane::Audit,
        &iam_domain::AccessEntry::Record(Box::new(record.clone())),
    )
}

fn answer(streams: &[Vec<(u64, String)>]) -> Vec<u8> {
    let result: Vec<Value> = streams
        .iter()
        .map(|values| {
            json!({
                "stream": { "lane": "audit" },
                "values": values
                    .iter()
                    .map(|(nanos, line)| json!([nanos.to_string(), line]))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "status": "success", "data": { "resultType": "streams", "result": result } })
        .to_string()
        .into_bytes()
}

#[test]
fn a_line_of_the_audit_sink_is_read_back_into_the_record_it_was_written_from() {
    let written = record(1);
    let body = answer(&[vec![(1_700_000_000_123_456_789, line_of(&written))]]);

    let entries = entries_of(&body).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].timestamp_nanos, 1_700_000_000_123_456_789);
    assert_eq!(entries[0].record, written);
}

#[test]
fn the_entries_of_several_streams_are_merged_newest_first() {
    let body = answer(&[
        vec![(30, line_of(&record(3))), (10, line_of(&record(1)))],
        vec![(20, line_of(&record(2)))],
    ]);

    let entries = entries_of(&body).unwrap();

    let nanos: Vec<u64> = entries.iter().map(|entry| entry.timestamp_nanos).collect();
    assert_eq!(nanos, [30, 20, 10]);
}

#[test]
fn entries_of_equal_timestamps_keep_the_order_of_loki() {
    let body = answer(&[vec![(5, line_of(&record(7))), (5, line_of(&record(8)))]]);

    let entries = entries_of(&body).unwrap();

    assert_eq!(entries[0].record, record(7));
    assert_eq!(entries[1].record, record(8));
}

#[test]
fn an_answer_without_entries_is_an_empty_list() {
    assert_eq!(entries_of(&answer(&[])).unwrap(), Vec::new());
    assert_eq!(entries_of(&answer(&[Vec::new()])).unwrap(), Vec::new());
}

#[test]
fn a_third_element_of_a_value_is_ignored() {
    let body = json!({
        "status": "success",
        "data": { "result": [{ "stream": {}, "values": [
            ["5", line_of(&record(1)), { "structuredMetadata": { "status": "403" } }]
        ] }] }
    })
    .to_string();

    assert_eq!(entries_of(body.as_bytes()).unwrap().len(), 1);
}

#[test]
fn an_answer_that_is_not_json_is_unavailable() {
    assert_eq!(
        entries_of(b"<html>502</html>"),
        Err(AccessLogQueryError::Unavailable)
    );
}

#[test]
fn an_answer_that_reports_an_error_status_is_unavailable() {
    let body = json!({ "status": "error", "data": { "result": [] } }).to_string();

    assert_eq!(
        entries_of(body.as_bytes()),
        Err(AccessLogQueryError::Unavailable)
    );
}

#[test]
fn an_entry_that_is_not_a_decision_makes_the_answer_unusable() {
    let aggregate = json!({ "kind": "aggregate", "lane": "access" }).to_string();
    let body = answer(&[vec![(5, aggregate)]]);

    assert_eq!(entries_of(&body), Err(AccessLogQueryError::Unavailable));
}

#[test]
fn a_complete_line_of_another_kind_makes_the_answer_unusable() {
    let mut line: Value = serde_json::from_str(&line_of(&record(1))).unwrap();
    line["kind"] = json!("aggregate");
    let body = answer(&[vec![(5, line.to_string())]]);

    assert_eq!(entries_of(&body), Err(AccessLogQueryError::Unavailable));
}

#[test]
fn a_line_that_is_not_json_makes_the_answer_unusable() {
    let body = answer(&[vec![(5, "plain text".to_owned())]]);

    assert_eq!(entries_of(&body), Err(AccessLogQueryError::Unavailable));
}

#[test]
fn a_value_without_a_numeric_timestamp_makes_the_answer_unusable() {
    let body = json!({
        "status": "success",
        "data": { "result": [{ "stream": {}, "values": [["soon", line_of(&record(1))]] }] }
    })
    .to_string();

    assert_eq!(
        entries_of(body.as_bytes()),
        Err(AccessLogQueryError::Unavailable)
    );
}

#[test]
fn a_value_without_a_line_makes_the_answer_unusable() {
    let body = json!({
        "status": "success",
        "data": { "result": [{ "stream": {}, "values": [["5"]] }] }
    })
    .to_string();

    assert_eq!(
        entries_of(body.as_bytes()),
        Err(AccessLogQueryError::Unavailable)
    );
}

#[test]
fn a_line_with_an_unknown_decision_or_reason_makes_the_answer_unusable() {
    for (field, value) in [
        ("decision", "maybe"),
        ("reason", "because"),
        ("decision_id", "nope"),
        ("subject_kind", "robot"),
    ] {
        let mut line: Value = serde_json::from_str(&line_of(&record(1))).unwrap();
        line[field] = json!(value);
        let body = answer(&[vec![(5, line.to_string())]]);

        assert_eq!(
            entries_of(&body),
            Err(AccessLogQueryError::Unavailable),
            "{field}"
        );
    }
}
