use std::error::Error as _;
use std::time::Duration;

use bytes::Bytes;
use iam_domain::{PolicyLogError, PolicyLogRecord};
use krafka::KrafkaError;
use krafka::error::ErrorCode;

use super::{
    KrafkaPolicyLogProducer, RelayMode, TRANSACTIONAL_ID, classify, is_fenced,
    reported_after_abort, stored_offset, to_record,
};
use crate::kafka::settings::{KafkaSecurity, KafkaSettings};

fn record(payload: Option<&str>, partition: Option<i32>) -> PolicyLogRecord {
    PolicyLogRecord {
        topic: "iam.policy.state.v1".to_owned(),
        key: "role/1".to_owned(),
        partition,
        payload: payload.map(str::to_owned),
        headers: vec![
            ("iam-version", "5".to_owned()),
            ("iam-relay-epoch", "2".to_owned()),
        ],
    }
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
fn a_state_record_becomes_a_keyed_record_on_its_partition_with_its_headers() {
    let built = to_record(&record(Some("{}"), Some(0)));

    assert_eq!(built.topic, "iam.policy.state.v1");
    assert_eq!(built.key, Some(Bytes::from("role/1")));
    assert_eq!(built.value, Some(Bytes::from("{}")));
    assert_eq!(built.partition, Some(0));
    assert_eq!(
        built.headers,
        [
            ("iam-version".to_owned(), Some(Bytes::from("5"))),
            ("iam-relay-epoch".to_owned(), Some(Bytes::from("2"))),
        ]
    );
}

#[test]
fn a_tombstone_has_no_value_and_keeps_its_headers() {
    let built = to_record(&record(None, Some(0)));

    assert_eq!(built.value, None);
    assert_eq!(built.key, Some(Bytes::from("role/1")));
    assert_eq!(built.headers.len(), 2);
}

#[test]
fn a_record_without_a_partition_leaves_the_choice_to_the_producer() {
    let built = to_record(&record(Some("{}"), None));

    assert_eq!(built.partition, None);
}

#[test]
fn a_fenced_producer_is_a_fencing_error() {
    let fenced = [
        KrafkaError::fenced("newer instance"),
        KrafkaError::broker(ErrorCode::ProducerFenced, "fenced"),
        KrafkaError::broker(ErrorCode::InvalidProducerEpoch, "old epoch"),
    ];

    for error in &fenced {
        assert!(is_fenced(error));
        assert!(matches!(classify(error), PolicyLogError::Fenced(_)));
    }
}

#[test]
fn every_other_failure_is_unavailable_and_keeps_its_cause() {
    let error = KrafkaError::broker(ErrorCode::RequestTimedOut, "moved");

    let classified = classify(&error);

    assert!(!is_fenced(&error));
    assert!(matches!(classified, PolicyLogError::Unavailable(_)));
    assert!(classified.source().is_some());
}

#[test]
fn a_producer_opens_nothing_until_it_publishes() {
    let producer = KrafkaPolicyLogProducer::new(&settings(), RelayMode::EpochOnly);
    producer.discard_session();
    drop(producer);
    let renamed = KrafkaPolicyLogProducer::new(&settings(), RelayMode::EpochOnly)
        .with_transactional_id("iam-relay-test".to_owned());
    assert_eq!(renamed.transactional_id, "iam-relay-test");
    drop(renamed);

    assert_eq!(TRANSACTIONAL_ID, "iam-relay");
    assert_ne!(
        RelayMode::Transactional {
            transaction_timeout: Duration::from_secs(10)
        },
        RelayMode::EpochOnly
    );
}

#[test]
fn a_fenced_abort_replaces_the_error_and_any_other_abort_keeps_it() {
    let produce = || KrafkaError::transaction_abortable("InvalidProducerEpoch");

    let aborted = reported_after_abort(produce(), Ok(()));
    let fenced = reported_after_abort(
        produce(),
        Err(KrafkaError::broker(ErrorCode::ProducerFenced, "fenced")),
    );
    let lost = reported_after_abort(
        produce(),
        Err(KrafkaError::broker(ErrorCode::RequestTimedOut, "moved")),
    );

    assert!(matches!(aborted, KrafkaError::TransactionAbortable { .. }));
    assert!(is_fenced(&fenced));
    assert!(matches!(lost, KrafkaError::TransactionAbortable { .. }));
}

#[test]
fn only_a_stored_record_has_an_offset() {
    assert_eq!(stored_offset(true, 42).unwrap(), 42);
    assert!(matches!(
        stored_offset(false, -1),
        Err(KrafkaError::IllegalState { .. })
    ));
}
