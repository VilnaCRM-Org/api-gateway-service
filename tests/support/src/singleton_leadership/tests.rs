use std::time::UNIX_EPOCH;

use iam_domain::{Leadership, RepositoryError, SingletonLeadership as _, SingletonTask};

use super::{Event, FakeSingletonLeadership, Step};
use crate::block_on;

const TASK: SingletonTask = SingletonTask::new("fake", 1);

#[test]
fn the_script_is_followed_and_then_the_default_repeats() {
    let leadership = FakeSingletonLeadership::new(&[Step::Follow], Step::Lead);

    let first = block_on(leadership.begin(&TASK)).unwrap();
    let second = block_on(leadership.begin(&TASK)).unwrap();

    assert!(matches!(first, Leadership::Follower));
    assert!(matches!(second, Leadership::Leader(_)));
}

#[test]
fn a_failing_step_is_an_unavailable_storage() {
    let leadership = FakeSingletonLeadership::new(&[], Step::Fail);

    let error = block_on(leadership.begin(&TASK)).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(leadership.events(), [Event::Begun("fake".to_owned())]);
}

#[test]
fn a_led_batch_records_and_commits() {
    let leadership = FakeSingletonLeadership::leading();
    let Leadership::Leader(mut batch) = block_on(leadership.begin(&TASK)).unwrap() else {
        panic!("the batch must be led");
    };

    block_on(batch.record_run(UNIX_EPOCH)).unwrap();
    block_on(batch.commit()).unwrap();

    assert_eq!(
        leadership.events(),
        [
            Event::Begun("fake".to_owned()),
            Event::Recorded(UNIX_EPOCH),
            Event::Committed,
        ]
    );
}

#[test]
fn a_led_batch_can_roll_back() {
    let leadership = FakeSingletonLeadership::leading();
    let Leadership::Leader(batch) = block_on(leadership.begin(&TASK)).unwrap() else {
        panic!("the batch must be led");
    };

    block_on(batch.rollback()).unwrap();

    assert_eq!(leadership.events().last(), Some(&Event::RolledBack));
}

#[test]
fn a_batch_can_fail_to_record_and_to_commit() {
    let leadership = FakeSingletonLeadership::new(
        &[Step::LeadFailingRecord, Step::LeadFailingCommit],
        Step::Lead,
    );
    let Leadership::Leader(mut recording) = block_on(leadership.begin(&TASK)).unwrap() else {
        panic!("the batch must be led");
    };
    let Leadership::Leader(committing) = block_on(leadership.begin(&TASK)).unwrap() else {
        panic!("the batch must be led");
    };

    assert!(block_on(recording.record_run(UNIX_EPOCH)).is_err());
    assert!(block_on(committing.commit()).is_err());
}
