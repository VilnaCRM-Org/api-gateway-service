use std::error::Error as _;

use shared_domain::Uuid;

use super::{LOG_SCHEMA, PolicyLogError, PolicyLogRecord};
use crate::{LogEpoch, OutboxKind, OutboxRow, PolicyDigestValue, PolicyVersion, RelayEpoch};

fn state_row(payload: Option<&str>) -> OutboxRow {
    OutboxRow {
        id: Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap(),
        kind: OutboxKind::State,
        topic: "iam.policy.state.v1".to_owned(),
        record_key: "role/1".to_owned(),
        payload: payload.map(str::to_owned),
        policy_version: PolicyVersion::new(5).unwrap(),
        seq: Some(1),
        count: Some(2),
        digest_after: Some(PolicyDigestValue::ZERO),
        log_epoch: LogEpoch::new(4).unwrap(),
        event_type: None,
    }
}

fn event_row() -> OutboxRow {
    OutboxRow {
        kind: OutboxKind::Event,
        topic: "iam.events.v1".to_owned(),
        payload: Some("{}".to_owned()),
        seq: None,
        count: None,
        digest_after: None,
        event_type: Some("iam.role.created".to_owned()),
        ..state_row(None)
    }
}

fn header<'a>(record: &'a PolicyLogRecord, name: &str) -> Option<&'a str> {
    record
        .headers
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn a_state_record_carries_every_header_in_order() {
    let record = PolicyLogRecord::of(&state_row(Some("{}")), RelayEpoch::new(9).unwrap());

    let names: Vec<_> = record.headers.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "iam-version",
            "iam-seq",
            "iam-count",
            "iam-digest-after",
            "iam-op",
            "iam-schema",
            "iam-log-epoch",
            "iam-relay-epoch",
        ]
    );
    assert_eq!(header(&record, "iam-version"), Some("5"));
    assert_eq!(header(&record, "iam-seq"), Some("1"));
    assert_eq!(header(&record, "iam-count"), Some("2"));
    assert_eq!(
        header(&record, "iam-digest-after"),
        Some(PolicyDigestValue::ZERO.to_hex().as_str())
    );
    assert_eq!(header(&record, "iam-op"), Some("upsert"));
    assert_eq!(header(&record, "iam-schema"), Some(LOG_SCHEMA));
    assert_eq!(header(&record, "iam-log-epoch"), Some("4"));
    assert_eq!(header(&record, "iam-relay-epoch"), Some("9"));
    assert_eq!(record.topic, "iam.policy.state.v1");
    assert_eq!(record.key, "role/1");
    assert_eq!(record.partition, Some(0));
    assert_eq!(record.payload.as_deref(), Some("{}"));
}

#[test]
fn a_tombstone_is_a_delete_without_a_value_and_keeps_its_headers() {
    let record = PolicyLogRecord::of(&state_row(None), RelayEpoch::new(1).unwrap());

    assert_eq!(record.payload, None);
    assert_eq!(header(&record, "iam-op"), Some("delete"));
    assert_eq!(header(&record, "iam-relay-epoch"), Some("1"));
}

#[test]
fn an_event_record_leaves_the_state_framing_out() {
    let record = PolicyLogRecord::of(&event_row(), RelayEpoch::new(1).unwrap());

    assert_eq!(header(&record, "iam-op"), Some("event"));
    assert_eq!(record.partition, None);
    assert_eq!(header(&record, "iam-seq"), None);
    assert_eq!(header(&record, "iam-count"), None);
    assert_eq!(header(&record, "iam-digest-after"), None);
    assert_eq!(record.headers.len(), 5);
}

#[test]
fn the_errors_name_what_failed_and_chain_their_cause() {
    let unavailable = PolicyLogError::Unavailable("broker down".into());
    let fenced = PolicyLogError::Fenced("old epoch".into());

    assert_eq!(
        unavailable.to_string(),
        "the Kafka cluster did not accept the records"
    );
    assert_eq!(unavailable.source().unwrap().to_string(), "broker down");
    assert_eq!(
        fenced.to_string(),
        "the producer was fenced by a newer relay"
    );
    assert_eq!(fenced.source().unwrap().to_string(), "old epoch");
}
