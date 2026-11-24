use bytes::Bytes;
use iam_domain::PolicyLogTailError;
use krafka::consumer::ConsumerRecord;

use std::time::Duration;

use super::{
    KrafkaPolicyLogTail, completed, finished, into_unavailable, polls_within, record_of,
    report_close, take_range,
};
use crate::kafka::settings::{KafkaSecurity, KafkaSettings};
use iam_domain::TAIL_READ_LIMIT;

fn consumed(offset: i64, key: Option<&str>, value: Option<&str>) -> ConsumerRecord {
    let mut record = ConsumerRecord::new(
        "iam.policy.state.v1",
        0,
        offset,
        key.map(|key| Bytes::from(key.to_owned())),
        value.map(|value| Bytes::from(value.to_owned())),
    );
    record.headers = vec![
        ("iam-version".to_owned(), Some(Bytes::from_static(b"7"))),
        ("iam-relay-epoch".to_owned(), Some(Bytes::from_static(b"3"))),
    ];
    record
}

#[test]
fn a_consumed_record_becomes_a_tail_record() {
    let record = record_of(&consumed(12, Some("role/1"), Some("{}"))).unwrap();

    assert_eq!(record.offset, 12);
    assert_eq!(record.key, "role/1");
    assert_eq!(record.payload.as_deref(), Some("{}"));
    assert_eq!(record.version.value(), 7);
    assert_eq!(record.relay_epoch.value(), 3);
}

#[test]
fn a_tombstone_has_no_payload() {
    let record = record_of(&consumed(1, Some("role/1"), None)).unwrap();

    assert_eq!(record.payload, None);
}

#[test]
fn a_record_without_a_key_is_malformed() {
    let refused = record_of(&consumed(4, None, Some("{}")));

    assert!(matches!(
        refused,
        Err(PolicyLogTailError::Malformed { offset: 4 })
    ));
}

#[test]
fn a_value_that_is_not_text_is_malformed() {
    let mut record = consumed(5, Some("role/1"), Some("{}"));
    record.value = Some(Bytes::from_static(&[0xff, 0xfe]));

    assert!(matches!(
        record_of(&record),
        Err(PolicyLogTailError::Malformed { offset: 5 })
    ));
}

#[test]
fn a_record_without_its_framing_headers_is_malformed() {
    let mut record = consumed(6, Some("role/1"), Some("{}"));
    record.headers.clear();

    assert!(matches!(
        record_of(&record),
        Err(PolicyLogTailError::Malformed { offset: 6 })
    ));
}

#[test]
fn a_negative_or_unreadable_header_is_malformed() {
    for bad in [&b"-1"[..], b"x"] {
        let mut record = consumed(7, Some("role/1"), None);
        record.headers = vec![
            ("iam-version".to_owned(), Some(Bytes::copy_from_slice(bad))),
            ("iam-relay-epoch".to_owned(), Some(Bytes::from_static(b"1"))),
        ];
        assert!(record_of(&record).is_err());
        record.headers = vec![
            ("iam-version".to_owned(), Some(Bytes::from_static(b"1"))),
            (
                "iam-relay-epoch".to_owned(),
                Some(Bytes::copy_from_slice(bad)),
            ),
        ];
        assert!(record_of(&record).is_err());
    }
}

#[test]
fn a_read_is_finished_at_the_limit_or_when_the_consumer_is_past_the_range() {
    assert!(!finished(0, None, 5));
    assert!(!finished(1, Some(4), 5));
    assert!(finished(1, Some(5), 5));
    assert!(finished(TAIL_READ_LIMIT, Some(0), i64::MAX));
}

#[test]
fn only_the_records_inside_the_range_are_taken() {
    let polled = vec![
        consumed(1, Some("role/1"), None),
        consumed(2, Some("role/2"), None),
        consumed(3, Some("role/3"), None),
    ];
    let mut records = Vec::new();

    take_range(&mut records, polled, 2, 3).unwrap();

    let offsets: Vec<_> = records.iter().map(|record| record.offset).collect();
    assert_eq!(offsets, [2]);
}

#[test]
fn a_malformed_record_in_the_range_fails_the_read() {
    let mut records = Vec::new();

    let failed = take_range(&mut records, vec![consumed(2, None, None)], 0, 10);

    assert!(failed.is_err());
}

#[test]
fn the_polls_fit_the_request_timeout_and_are_at_least_one() {
    assert_eq!(polls_within(Duration::from_secs(2)), 10);
    assert_eq!(polls_within(Duration::from_millis(10)), 1);
}

fn settings() -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: "localhost:9092".to_owned(),
        security: KafkaSecurity::Plaintext,
        client_id: "iam-control".to_owned(),
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        retry_delay: Duration::from_millis(100),
        gates: iam_domain::ConfigGates::Relaxed,
        policy_topic: "iam.policy.state.v1".to_owned(),
        events_topic: "iam.events.v1".to_owned(),
    }
}

#[test]
fn the_reader_prints_its_topic_and_nothing_of_its_settings() {
    let printed = format!("{:?}", KrafkaPolicyLogTail::new(settings()));

    assert_eq!(
        printed,
        "KrafkaPolicyLogTail { topic: \"iam.policy.state.v1\", .. }"
    );
}

#[test]
fn a_read_that_did_not_finish_in_time_is_unavailable_and_a_finished_one_is_cut_at_the_limit() {
    let many: Vec<_> = (0..)
        .take(TAIL_READ_LIMIT.saturating_add(1))
        .map(|offset| record_of(&consumed(offset, Some("role/a"), Some("{}"))).unwrap())
        .collect();

    assert!(matches!(
        completed(Vec::new(), false),
        Err(PolicyLogTailError::Unavailable(_))
    ));
    assert_eq!(completed(many, true).unwrap().len(), TAIL_READ_LIMIT);
}

#[test]
fn a_client_error_is_an_unavailable_topic() {
    assert!(matches!(
        into_unavailable(krafka::KrafkaError::timeout("poll")),
        PolicyLogTailError::Unavailable(_)
    ));
}

#[test]
fn a_close_that_fails_is_reported_and_a_clean_one_is_not() {
    report_close(Err(krafka::KrafkaError::timeout("consumer close")));
    report_close(Ok(()));
}
