use iam_domain::StartupLock as _;

use super::FakeStartupLock;
use crate::block_on;

#[test]
fn a_taken_lock_is_held_until_its_guard_is_dropped() {
    let lock = FakeStartupLock::new();

    let guard = block_on(lock.acquire("first")).unwrap();
    assert_eq!(lock.held(), ["first"]);
    drop(guard);

    assert_eq!(lock.held(), Vec::<String>::new());
    assert_eq!(lock.taken(), ["first"]);
}

#[test]
fn every_taken_name_is_recorded_in_order() {
    let lock = FakeStartupLock::new();

    drop(block_on(lock.acquire("first")).unwrap());
    drop(block_on(lock.acquire("second")).unwrap());

    assert_eq!(lock.taken(), ["first", "second"]);
}

#[test]
fn a_failing_lock_is_unavailable_and_takes_nothing() {
    let lock = FakeStartupLock::failing();

    let error = block_on(lock.acquire("first")).unwrap_err();

    assert!(matches!(error, iam_domain::RepositoryError::Unavailable(_)));
    assert_eq!(lock.taken(), Vec::<String>::new());
}
