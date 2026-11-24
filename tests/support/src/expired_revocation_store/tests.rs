use std::time::{Duration, SystemTime};

use iam_domain::{ExpiredRevocation, ExpiredRevocationStore as _, RepositoryError, SessionId};

use super::FakeExpiredRevocationStore;
use crate::block_on;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap()
}

fn session(id: &str, prune_after: u64) -> ExpiredRevocation {
    ExpiredRevocation::Session {
        session: SessionId::new(id).unwrap(),
        prune_after: at(prune_after),
    }
}

#[test]
fn only_records_strictly_before_the_instant_are_returned_oldest_first() {
    let store = FakeExpiredRevocationStore::new().holding(vec![
        session("late", 200),
        session("exact", 150),
        session("early", 100),
        session("earlier", 50),
    ]);

    let expired = block_on(store.expired_revocations(at(150), 10)).unwrap();

    assert_eq!(expired, vec![session("earlier", 50), session("early", 100)]);
}

#[test]
fn the_limit_caps_the_answer() {
    let store = FakeExpiredRevocationStore::new().holding(vec![session("a", 1), session("b", 2)]);

    let expired = block_on(store.expired_revocations(at(10), 1)).unwrap();

    assert_eq!(expired, vec![session("a", 1)]);
}

#[test]
fn the_requests_are_recorded() {
    let store = FakeExpiredRevocationStore::default();

    block_on(store.expired_revocations(at(7), 3)).unwrap();

    assert_eq!(store.requests(), vec![(at(7), 3)]);
}

#[test]
fn a_failing_store_is_unavailable() {
    let store = FakeExpiredRevocationStore::failing();

    let refused = block_on(store.expired_revocations(at(7), 3));

    assert!(matches!(refused, Err(RepositoryError::Unavailable(_))));
}
