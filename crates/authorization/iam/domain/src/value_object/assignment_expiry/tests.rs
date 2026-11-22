use std::time::{Duration, SystemTime};

use rstest::rstest;

use super::AssignmentExpiry;
use crate::error::InvalidUserRole;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

#[test]
fn an_expiry_after_now_is_accepted() {
    let expiry = AssignmentExpiry::new(at(101), at(100)).unwrap();

    assert_eq!(expiry.at(), at(101));
}

#[rstest]
#[case(100)]
#[case(99)]
#[case(0)]
fn an_expiry_that_is_not_after_now_is_refused(#[case] seconds: u64) {
    assert_eq!(
        AssignmentExpiry::new(at(seconds), at(100)),
        Err(InvalidUserRole::ExpiryNotInFuture)
    );
}

#[test]
fn a_restored_expiry_may_lie_in_the_past() {
    assert_eq!(AssignmentExpiry::restore(at(5)).at(), at(5));
}

#[rstest]
#[case(99, false)]
#[case(100, true)]
#[case(101, true)]
fn an_expiry_has_passed_from_its_instant_on(#[case] now: u64, #[case] passed: bool) {
    assert_eq!(
        AssignmentExpiry::restore(at(100)).has_passed(at(now)),
        passed
    );
}
