use std::sync::Arc;

use iam_domain::{
    CatalogueEntryState, InvalidStateRecord, PolicyDigestValue, PolicyLogTail, PolicyState,
    PolicyVersion, StateKey, StateRecordCodec, SubjectRef, SubjectState,
};
use shared_domain::Uuid;
use test_support::anti_entropy::{FakePolicyLogTail, TextHeadCodec, head_record, tail_record};

use super::PolicyTopicHead;
use crate::error::IamError;

fn reader(tail: FakePolicyLogTail) -> (PolicyTopicHead, Arc<FakePolicyLogTail>) {
    let tail = Arc::new(tail);
    let port: Arc<dyn PolicyLogTail> = Arc::<FakePolicyLogTail>::clone(&tail);
    let reader = PolicyTopicHead::new(port, Arc::new(TextHeadCodec));
    (reader, tail)
}

fn digest() -> PolicyDigestValue {
    PolicyDigestValue::ZERO
}

#[tokio::test]
async fn an_empty_topic_has_no_version() {
    let (reader, _tail) = reader(FakePolicyLogTail::with(Vec::new()));

    assert_eq!(reader.highest_version().await.unwrap(), None);
}

#[tokio::test]
async fn the_highest_head_of_the_newest_window_is_the_topic_version() {
    let records = vec![
        tail_record(0, "role/x", Some("{}"), 3, 1),
        head_record(1, 3, digest(), 1),
        head_record(2, 9, digest(), 1),
        tail_record(3, "role/y", Some("{}"), 9, 1),
        head_record(4, 7, digest(), 1),
    ];
    let (reader, _tail) = reader(FakePolicyLogTail::with(records));

    let version = reader.highest_version().await.unwrap();

    assert_eq!(version.map(PolicyVersion::value), Some(9));
}

#[tokio::test]
async fn a_topic_without_a_readable_head_has_no_version() {
    let records = vec![
        tail_record(0, "role/x", Some("{}"), 3, 1),
        tail_record(1, "__head", Some("not a head"), 4, 1),
        tail_record(2, "__head", None, 5, 1),
    ];
    let (reader, _tail) = reader(FakePolicyLogTail::with(records));

    assert_eq!(reader.highest_version().await.unwrap(), None);
}

#[tokio::test]
async fn a_head_older_than_one_window_is_still_found() {
    let mut records = vec![head_record(0, 4, digest(), 1)];
    records.extend((1..1_200).map(|offset| tail_record(offset, "role/x", Some("{}"), 4, 1)));
    let (reader, _tail) = reader(FakePolicyLogTail::with(records));

    let version = reader.highest_version().await.unwrap();

    assert_eq!(version.map(PolicyVersion::value), Some(4));
}

#[tokio::test]
async fn the_connection_is_released_after_a_read() {
    let (reader, tail) = reader(FakePolicyLogTail::with(vec![head_record(
        0,
        2,
        digest(),
        1,
    )]));

    reader.highest_version().await.unwrap();

    assert_eq!(tail.closes(), 1);
}

#[tokio::test]
async fn an_unreachable_cluster_is_a_storage_failure_and_the_connection_is_still_released() {
    let (reader, tail) = reader(FakePolicyLogTail::with(Vec::new()).unavailable());

    let error = reader.highest_version().await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(tail.closes(), 1);
}

/// A codec whose every record is the state of a subject, so that a head decodes to the state of
/// another entity.
#[derive(Debug)]
struct SubjectCodec(SubjectRef);

impl StateRecordCodec for SubjectCodec {
    fn encode(&self, _state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Err(InvalidStateRecord::Encoding)
    }

    fn decode(&self, _key: &StateKey, _payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        Ok(PolicyState::Subject(SubjectState {
            subject: self.0.clone(),
            assignments: Vec::new(),
        }))
    }

    fn entry_size(&self, _entry: &CatalogueEntryState) -> usize {
        0
    }
}

#[tokio::test]
async fn a_head_that_decodes_to_another_entity_does_not_count() {
    let tail: Arc<dyn PolicyLogTail> = Arc::new(FakePolicyLogTail::with(vec![head_record(
        0,
        5,
        digest(),
        1,
    )]));
    let reader = PolicyTopicHead::new(
        tail,
        Arc::new(SubjectCodec(SubjectRef::user(
            Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap(),
        ))),
    );

    assert_eq!(reader.highest_version().await.unwrap(), None);
}
