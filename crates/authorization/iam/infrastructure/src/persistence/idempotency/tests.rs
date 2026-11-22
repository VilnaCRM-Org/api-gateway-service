use std::error::Error as _;
use std::time::Duration;

use super::*;

fn actor() -> ActorRef {
    ActorRef::parse("user:0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()
}

fn key() -> IdempotencyKey {
    IdempotencyKey::new("key-1").unwrap()
}

fn change_uuid() -> SqlUuid {
    Uuid::parse("0190f2a8-7b3c-7d4e-8f00-000000000001")
        .unwrap()
        .as_uuid()
}

#[test]
fn a_valid_row_is_restored_with_the_actor_the_key_the_digest_and_the_change() {
    let row = Row {
        request_digest: vec![7; 32],
        change_id: change_uuid(),
    };

    let record = restore(&actor(), &key(), &row).unwrap();

    assert_eq!(record.actor(), &actor());
    assert_eq!(record.key(), &key());
    assert_eq!(
        record.request_digest(),
        RequestDigest::new(&[7; 32]).unwrap()
    );
    assert_eq!(record.change_id().as_uuid().as_uuid(), change_uuid());
}

#[test]
fn a_row_with_a_digest_of_another_length_is_unavailable() {
    let row = Row {
        request_digest: vec![7; 31],
        change_id: change_uuid(),
    };

    let error = restore(&actor(), &key(), &row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_time_is_its_timestamp_to_the_nanosecond() {
    let time = UNIX_EPOCH + Duration::new(1_800_000_000, 123_456_789);

    let stamp = timestamp(time).unwrap();

    assert_eq!(stamp.unix_timestamp(), 1_800_000_000);
    assert_eq!(stamp.nanosecond(), 123_456_789);
}

#[test]
fn the_epoch_is_a_valid_timestamp() {
    assert_eq!(timestamp(UNIX_EPOCH).unwrap().unix_timestamp(), 0);
}

#[test]
fn a_time_before_1970_is_unavailable() {
    let error = timestamp(UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap()).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_time_after_the_year_9999_is_unavailable() {
    let error = timestamp(
        UNIX_EPOCH
            .checked_add(Duration::from_hours(70_389_528))
            .unwrap(),
    )
    .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}
