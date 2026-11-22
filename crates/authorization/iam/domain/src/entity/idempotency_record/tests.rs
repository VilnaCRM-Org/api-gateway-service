use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{IdempotencyRecord, IdempotencyRequest};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::ChangeId;
use crate::value_object::request_digest::RequestDigest;

#[test]
fn a_record_keeps_the_actor_the_key_the_digest_and_the_change() {
    let actor = ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap());
    let key = IdempotencyKey::new("key-1").unwrap();
    let digest = RequestDigest::new(&[7; 32]).unwrap();
    let change_id = ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap();
    let request = IdempotencyRequest {
        key: key.clone(),
        request_digest: digest,
    };

    let record = IdempotencyRecord::new(actor.clone(), request, change_id);

    assert_eq!(record.actor(), &actor);
    assert_eq!(record.key(), &key);
    assert_eq!(record.request_digest(), digest);
    assert_eq!(record.change_id(), change_id);
}

fn record_with_digest(byte: u8) -> IdempotencyRecord {
    let actor = ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("key-1").unwrap(),
        request_digest: RequestDigest::new(&[byte; 32]).unwrap(),
    };
    let change_id = ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap();
    IdempotencyRecord::new(actor, request, change_id)
}

#[test]
fn the_window_is_24_hours() {
    assert_eq!(IdempotencyRecord::WINDOW, Duration::from_hours(24));
}

#[test]
fn the_window_starts_24_hours_before_now() {
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();

    let start = IdempotencyRecord::window_start(now);

    assert_eq!(
        start,
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(499_976))
            .unwrap()
    );
}

#[test]
fn the_window_starts_at_the_epoch_when_now_is_closer_to_it_than_24_hours() {
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(86_399))
        .unwrap();

    assert_eq!(IdempotencyRecord::window_start(now), SystemTime::UNIX_EPOCH);
}

#[test]
fn the_window_starts_at_the_epoch_when_now_is_before_it() {
    let now = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(5))
        .unwrap();

    assert_eq!(IdempotencyRecord::window_start(now), SystemTime::UNIX_EPOCH);
}

#[test]
fn the_window_starts_one_second_after_the_epoch_24_hours_and_a_second_after_it() {
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(86_401))
        .unwrap();

    assert_eq!(
        IdempotencyRecord::window_start(now),
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1))
            .unwrap()
    );
}

#[test]
fn the_window_starts_at_the_epoch_exactly_24_hours_after_it() {
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(24))
        .unwrap();

    assert_eq!(IdempotencyRecord::window_start(now), SystemTime::UNIX_EPOCH);
}

#[test]
fn a_repeat_with_the_recorded_digest_replays_the_recorded_change() {
    let record = record_with_digest(7);

    let replayed = record.replay(RequestDigest::new(&[7; 32]).unwrap());

    assert_eq!(replayed, Some(record.change_id()));
}

#[test]
fn a_repeat_with_another_digest_replays_nothing() {
    let record = record_with_digest(7);

    assert_eq!(record.replay(RequestDigest::new(&[8; 32]).unwrap()), None);
}
