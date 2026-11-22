use std::error::Error as _;

use iam_domain::RepositoryError;
use rstest::rstest;
use shared_application::http::{Problem, TYPE_BLANK, Violation};
use test_support::log::LogRecorder;

use super::IamError;

#[test]
fn not_found_is_the_404_problem_with_its_message_and_is_not_logged() {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(IamError::NotFound);

    assert_eq!(problem.status, 404);
    assert_eq!(problem.title, "Not Found");
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("The requested IAM record was not found.")
    );
    assert_eq!(problem.violations, Vec::<Violation>::new());
    assert_eq!(recorder.lines().len(), 0);
}

#[test]
fn a_storage_failure_is_the_internal_problem_and_is_logged_once() {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(IamError::Storage("disk on fire".into()));

    assert_eq!(problem.status, 500);
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(problem.detail, None);
    assert_eq!(problem.violations, Vec::<Violation>::new());
    assert_eq!(recorder.lines().len(), 1);
}

#[test]
fn a_conflict_is_the_409_problem_with_its_message_and_is_not_logged() {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(IamError::Conflict);

    assert_eq!(problem.status, 409);
    assert_eq!(problem.title, "Conflict");
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("The IAM record conflicts with its current state.")
    );
    assert_eq!(problem.violations, Vec::<Violation>::new());
    assert_eq!(recorder.lines().len(), 0);
}

#[rstest]
#[case(RepositoryError::AlreadyExists)]
#[case(RepositoryError::Conflict)]
fn an_existing_or_concurrently_changed_record_is_a_conflict(#[case] repository: RepositoryError) {
    let error = IamError::from(repository);

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(
        error.to_string(),
        "The IAM record conflicts with its current state."
    );
    assert!(error.source().is_none());
}

#[test]
fn a_missing_record_of_the_repository_is_not_found() {
    let error = IamError::from(RepositoryError::NotFound);

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(error.to_string(), "The requested IAM record was not found.");
    assert!(error.source().is_none());
}

#[test]
fn an_unavailable_repository_is_a_storage_failure_that_keeps_the_chain() {
    let error = IamError::from(RepositoryError::Unavailable("disk on fire".into()));

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(error.to_string(), "the IAM storage is unavailable");
    let repository = error.source().unwrap();
    assert_eq!(repository.to_string(), "the repository is unavailable");
    assert_eq!(repository.source().unwrap().to_string(), "disk on fire");
}
