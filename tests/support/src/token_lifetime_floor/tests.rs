use std::time::Duration;

use iam_domain::{RepositoryError, TokenLifetimeFloor as _};

use super::FakeTokenLifetimeFloor;
use crate::block_on;

#[test]
fn a_new_floor_holds_no_value() {
    assert_eq!(
        block_on(FakeTokenLifetimeFloor::new().longest()).unwrap(),
        None
    );
}

#[test]
fn raising_stores_the_value_and_a_lower_value_never_lowers_it() {
    let floor = FakeTokenLifetimeFloor::new();

    assert_eq!(
        block_on(floor.raise_to(Duration::from_mins(15))).unwrap(),
        Duration::from_mins(15)
    );
    assert_eq!(
        block_on(floor.raise_to(Duration::from_mins(30))).unwrap(),
        Duration::from_mins(30)
    );
    assert_eq!(
        block_on(floor.raise_to(Duration::from_mins(15))).unwrap(),
        Duration::from_mins(30)
    );
    assert_eq!(
        block_on(floor.longest()).unwrap(),
        Some(Duration::from_mins(30))
    );
}

#[test]
fn a_failing_floor_is_unavailable() {
    let floor = FakeTokenLifetimeFloor::holding(Duration::from_mins(15));
    floor.fail(true);

    assert!(matches!(
        block_on(floor.longest()),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(floor.raise_to(Duration::from_mins(1))),
        Err(RepositoryError::Unavailable(_))
    ));
}
