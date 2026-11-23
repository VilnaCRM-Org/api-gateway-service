use std::time::SystemTime;

use iam_domain::{RepositoryError, TaskState, TaskStateRepository as _};

use super::FakeTaskStateRepository;
use crate::block_on;

fn state(run_count: u64) -> TaskState {
    TaskState {
        last_run_at: SystemTime::UNIX_EPOCH,
        run_count,
    }
}

#[test]
fn a_task_that_never_ran_has_no_state() {
    let repository = FakeTaskStateRepository::new();

    assert_eq!(block_on(repository.find("maintenance")).unwrap(), None);
}

#[test]
fn the_state_of_a_task_is_found_by_its_name() {
    let repository = FakeTaskStateRepository::new().with_state("maintenance", state(3));

    assert_eq!(
        block_on(repository.find("maintenance")).unwrap(),
        Some(state(3))
    );
    assert_eq!(block_on(repository.find("other")).unwrap(), None);
}

#[test]
fn a_failing_repository_answers_unavailable() {
    let repository = FakeTaskStateRepository::failing();

    assert!(matches!(
        block_on(repository.find("maintenance")),
        Err(RepositoryError::Unavailable(_))
    ));
}
