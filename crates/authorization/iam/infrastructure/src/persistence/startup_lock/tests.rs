use std::error::Error as _;

use super::unavailable;
use iam_domain::RepositoryError;

#[test]
fn a_database_failure_is_an_unavailable_repository_with_its_cause() {
    let error = unavailable(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}
