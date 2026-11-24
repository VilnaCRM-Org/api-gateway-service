use std::error::Error as _;

use rstest::rstest;

use super::RepositoryError;
use crate::error::ReferencedByRoute;

#[rstest]
#[case(RepositoryError::AlreadyExists, "the record already exists")]
#[case(RepositoryError::NotFound, "the record was not found")]
#[case(RepositoryError::Conflict, "the record was changed concurrently")]
#[case(
    RepositoryError::Forbidden,
    "the actor lacks the administrative rights of the change"
)]
fn displays_its_errors_without_a_source(#[case] error: RepositoryError, #[case] message: &str) {
    assert_eq!(error.to_string(), message);
    assert!(error.source().is_none());
}

#[test]
fn the_refusals_under_the_lock_chain_their_cause() {
    let referenced = RepositoryError::ReferencedByRoute(ReferencedByRoute { count: 2 });

    assert_eq!(referenced.to_string(), "a route still references the entry");
    assert_eq!(
        referenced.source().unwrap().to_string(),
        "2 route(s) still reference this entry."
    );
}

#[test]
fn an_unavailable_repository_chains_its_cause() {
    let unavailable = RepositoryError::Unavailable("disk on fire".into());

    assert_eq!(unavailable.to_string(), "the repository is unavailable");
    assert_eq!(unavailable.source().unwrap().to_string(), "disk on fire");
}
