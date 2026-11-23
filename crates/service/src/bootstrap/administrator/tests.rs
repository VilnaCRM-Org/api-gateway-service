use iam_application::IamError;

use super::{AdministratorError, refusal_of};

#[test]
fn a_conflict_means_the_administrator_exists_already() {
    assert!(matches!(
        refusal_of(IamError::Conflict),
        AdministratorError::AlreadyBootstrapped
    ));
}

#[test]
fn any_other_failure_is_a_failed_creation() {
    let error = refusal_of(IamError::Internal("the role could not be stored".into()));

    assert!(
        matches!(error, AdministratorError::Creation(IamError::Internal(_))),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the administrator could not be created: the IAM use case produced an invalid value"
    );
}
