use std::time::{Duration, SystemTime};

use iam_domain::{
    LogEpoch, OutboxKind, OutboxRow, OutboxStore as _, PolicyVersion, PublishedRow, RelayEpoch,
    RepositoryError,
};
use shared_domain::Uuid;

use super::{Failing, FakeOutboxStore};
use crate::block_on;

fn row(id: &str) -> OutboxRow {
    OutboxRow {
        id: Uuid::parse(id).unwrap(),
        kind: OutboxKind::Event,
        topic: "iam.events.v1".to_owned(),
        record_key: "key".to_owned(),
        payload: Some("{}".to_owned()),
        policy_version: PolicyVersion::new(1).unwrap(),
        seq: None,
        count: None,
        digest_after: None,
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: Some("iam.role.created".to_owned()),
    }
}

const FIRST: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890a1";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890a2";

fn epoch(value: i64) -> RelayEpoch {
    RelayEpoch::new(value).unwrap()
}

#[test]
fn claims_at_most_the_limit_in_order() {
    let store = FakeOutboxStore::default().with_rows(vec![row(FIRST), row(SECOND)]);

    let claimed = block_on(store.claim_unpublished(1)).unwrap();

    assert_eq!(claimed, vec![row(FIRST)]);
}

#[test]
fn marking_published_removes_the_rows_and_records_the_epoch() {
    let store = FakeOutboxStore::new()
        .with_rows(vec![row(FIRST)])
        .with_epoch(3);
    let published = PublishedRow {
        id: row(FIRST).id,
        offset: 4,
    };

    block_on(store.mark_published(&[published], epoch(3), SystemTime::UNIX_EPOCH)).unwrap();

    assert_eq!(store.unpublished(), 0);
    assert_eq!(store.published(), vec![(published, epoch(3))]);
}

#[test]
fn marking_under_a_stale_epoch_is_a_conflict() {
    let store = FakeOutboxStore::new().with_rows(vec![row(FIRST)]);
    store.another_relay_takes_over();

    let marked = block_on(store.mark_published(&[], epoch(0), SystemTime::UNIX_EPOCH));

    assert!(matches!(marked, Err(RepositoryError::Conflict)));
}

#[test]
fn a_takeover_increments_the_epoch_and_hands_over_the_republished_rows() {
    let store = FakeOutboxStore::new().with_republish(vec![row(SECOND)]);

    let takeover = block_on(store.take_over_relay()).unwrap();

    assert_eq!(takeover.epoch, epoch(1));
    assert_eq!(takeover.republish, vec![row(SECOND)]);
    assert_eq!(store.takeovers(), 1);
    assert_eq!(store.epoch(), 1);
    assert_eq!(block_on(store.current_relay_epoch()).unwrap(), epoch(1));
}

#[test]
fn deletions_record_their_cut_off() {
    let store = FakeOutboxStore::new();
    let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(9);

    let deleted = block_on(store.delete_published_before(cutoff)).unwrap();

    assert_eq!(deleted, 0);
    assert_eq!(store.deleted_before(), vec![cutoff]);
}

#[test]
fn a_failing_operation_is_unavailable() {
    for failing in [
        Failing::Claim,
        Failing::Epoch,
        Failing::Takeover,
        Failing::Mark,
        Failing::Delete,
    ] {
        let store = FakeOutboxStore::new().failing(failing);

        let results = [
            block_on(store.claim_unpublished(1)).is_err(),
            block_on(store.current_relay_epoch()).is_err(),
            block_on(store.mark_published(&[], epoch(0), SystemTime::UNIX_EPOCH)).is_err(),
            block_on(store.take_over_relay()).is_err(),
            block_on(store.delete_published_before(SystemTime::UNIX_EPOCH)).is_err(),
        ];

        assert_eq!(results.iter().filter(|failed| **failed).count(), 1);
    }
}
