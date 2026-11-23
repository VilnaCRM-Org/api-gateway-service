use std::error::Error as _;
use std::time::{Duration, UNIX_EPOCH};

use super::{restore, unavailable};
use iam_domain::RepositoryError;
use sqlx::types::time::OffsetDateTime;

#[test]
fn a_database_failure_is_an_unavailable_repository_with_its_cause() {
    let error = unavailable(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_stored_row_becomes_the_state_of_the_task() {
    let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    let state = restore(at, 3).unwrap();

    assert_eq!(state.run_count, 3);
    assert_eq!(
        state.last_run_at,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
}

#[test]
fn a_negative_run_count_is_unusable_data() {
    let at = OffsetDateTime::from_unix_timestamp(0).unwrap();

    let error = restore(at, -1).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}
