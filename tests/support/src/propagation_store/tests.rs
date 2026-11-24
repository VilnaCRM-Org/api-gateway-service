use iam_domain::{
    ChangeId, PolicyVersion, PropagationOutcome, PropagationStore as _, RepositoryError,
};
use shared_domain::Uuid;

use super::FakePropagationStore;
use crate::block_on;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn a_version_is_published_once_its_offset_is_stored() {
    let store = FakePropagationStore::new();

    assert_eq!(
        block_on(store.published_head_offset(version(4))).unwrap(),
        None
    );
    store.publish(4, 9);
    assert_eq!(
        block_on(store.published_head_offset(version(4))).unwrap(),
        Some(9)
    );
    assert_eq!(store.polls(), 2);
}

#[test]
fn a_store_built_with_an_offset_publishes_that_version() {
    let store = FakePropagationStore::publishing(2, 5);

    assert_eq!(
        block_on(store.published_head_offset(version(2))).unwrap(),
        Some(5)
    );
}

#[test]
fn the_recorded_outcomes_are_kept_in_order() {
    let store = FakePropagationStore::new();
    let change = ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap());

    block_on(store.record(change, PropagationOutcome::CommittedPending)).unwrap();

    assert_eq!(
        store.recorded(),
        vec![(change, PropagationOutcome::CommittedPending)]
    );
}

#[test]
fn a_failing_store_is_unavailable() {
    let store = FakePropagationStore::failing();
    let change = ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap());

    assert!(matches!(
        block_on(store.published_head_offset(version(1))),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(store.record(change, PropagationOutcome::CommittedPending)),
        Err(RepositoryError::Unavailable(_))
    ));
}
