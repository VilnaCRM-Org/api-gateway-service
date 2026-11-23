use std::error::Error as _;

use iam_domain::{
    EntityVersion, InvalidCatalogueEntry, InvalidEventEnvelope, InvalidIamValue, InvalidRole,
    InvalidUserRole, RepositoryError, RoleChangeRefused, TokenRejection, UserRoleChangeRefused,
    VersionConflict,
};
use rstest::rstest;
use shared_application::http::{Problem, TYPE_BLANK, Violation};
use test_support::log::LogRecorder;

use super::{Confirmation, IamError, TYPE_FLAG_DOWNGRADE_CONFIRMATION, TYPE_ORPHAN_CONFIRMATION};

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

#[rstest]
#[case::forbidden(
    IamError::Forbidden,
    403,
    "Forbidden",
    "The IAM record cannot be changed through the API."
)]
#[case::idempotency_mismatch(
    IamError::IdempotencyMismatch,
    422,
    "Unprocessable Entity",
    "The idempotency key was already used for a different request."
)]
#[case::precondition_required(
    IamError::PreconditionRequired,
    428,
    "Precondition Required",
    "The request must name the version it changes."
)]
#[case::precondition_failed(
    IamError::PreconditionFailed,
    412,
    "Precondition Failed",
    "The request names a version that is not the current version."
)]
fn a_client_error_is_its_problem_with_its_message_and_is_not_logged(
    #[case] error: IamError,
    #[case] status: u16,
    #[case] title: &str,
    #[case] detail: &str,
) {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(error);

    assert_eq!(problem.status, status);
    assert_eq!(problem.title, title);
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(problem.detail.as_deref(), Some(detail));
    assert_eq!(problem.violations, Vec::<Violation>::new());
    assert_eq!(recorder.lines().len(), 0);
}

#[test]
fn a_missing_version_is_a_required_precondition() {
    let error = IamError::from(VersionConflict::Missing);

    assert!(matches!(error, IamError::PreconditionRequired));
    assert!(error.source().is_none());
}

#[test]
fn a_stale_version_is_a_failed_precondition() {
    let conflict = VersionConflict::Stale {
        expected: EntityVersion::new(3).unwrap(),
        current: EntityVersion::new(4).unwrap(),
    };

    let error = IamError::from(conflict);

    assert!(matches!(error, IamError::PreconditionFailed));
    assert!(error.source().is_none());
}

#[test]
fn unauthenticated_is_the_401_problem_with_a_fixed_message_and_is_not_logged() {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(IamError::Unauthenticated);

    assert_eq!(problem.status, 401);
    assert_eq!(problem.title, "Unauthorized");
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("A valid bearer token is required.")
    );
    assert_eq!(problem.violations, Vec::<Violation>::new());
    assert_eq!(recorder.lines().len(), 0);
}

#[rstest]
#[case::missing(TokenRejection::Missing)]
#[case::invalid(TokenRejection::Invalid)]
#[case::expired(TokenRejection::Expired)]
#[case::revoked(TokenRejection::Revoked)]
fn every_refused_credential_is_unauthenticated(#[case] rejection: TokenRejection) {
    assert!(matches!(
        IamError::from(rejection),
        IamError::Unauthenticated
    ));
}

#[test]
fn an_unreadable_revocation_state_is_a_storage_failure() {
    let error = IamError::from(TokenRejection::Unavailable);

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("the credential could not be checked")
    );
}

#[test]
fn invalid_role_values_are_the_422_problem_with_one_violation_each_sorted_by_property() {
    let (recorder, _guard) = LogRecorder::install();

    let error = IamError::from(vec![
        InvalidRole::DescriptionLength,
        InvalidRole::NameLength,
    ]);
    let problem = Problem::from(error);

    assert_eq!(problem.status, 422);
    assert_eq!(problem.r#type, "/problems/validation-failed");
    assert_eq!(
        problem.violations,
        vec![
            Violation {
                property_path: "description".to_owned(),
                message: "This value must contain 1000 characters or fewer.".to_owned(),
                code: "length".to_owned(),
            },
            Violation {
                property_path: "name".to_owned(),
                message: "This value must contain between 1 and 100 characters.".to_owned(),
                code: "length".to_owned(),
            },
        ]
    );
    assert_eq!(recorder.lines().len(), 0);
}

#[test]
fn the_message_of_invalid_values_is_fixed() {
    assert_eq!(
        IamError::Invalid(Vec::new()).to_string(),
        "The request holds invalid values."
    );
}

#[test]
fn a_value_that_the_use_case_produced_wrongly_is_the_internal_problem_and_is_logged_once() {
    let (recorder, _guard) = LogRecorder::install();

    let problem = Problem::from(IamError::from(InvalidIamValue::AuditTimestamp));

    assert_eq!(problem.status, 500);
    assert_eq!(problem.detail, None);
    assert_eq!(recorder.lines().len(), 1);
}

#[test]
fn an_invalid_envelope_is_an_internal_failure_that_names_its_cause() {
    let error = IamError::from(InvalidEventEnvelope::EventType);

    assert!(matches!(error, IamError::Internal(_)));
    assert_eq!(
        error.to_string(),
        "the IAM use case produced an invalid value"
    );
    assert_eq!(
        error.source().map(ToString::to_string),
        Some(InvalidEventEnvelope::EventType.to_string())
    );
}

#[test]
fn a_system_role_refusal_is_forbidden() {
    let error = IamError::from(RoleChangeRefused::SystemRole);

    assert!(matches!(error, IamError::Forbidden));
}

#[test]
fn a_deleted_role_refusal_is_not_found() {
    let error = IamError::from(RoleChangeRefused::Deleted);

    assert!(matches!(error, IamError::NotFound));
}

#[test]
fn a_missing_version_refusal_is_a_required_precondition() {
    let error = IamError::from(RoleChangeRefused::Version(VersionConflict::Missing));

    assert!(matches!(error, IamError::PreconditionRequired));
}

#[test]
fn a_stale_version_refusal_is_a_failed_precondition() {
    let conflict = VersionConflict::Stale {
        expected: EntityVersion::new(1).unwrap(),
        current: EntityVersion::new(2).unwrap(),
    };

    let error = IamError::from(RoleChangeRefused::Version(conflict));

    assert!(matches!(error, IamError::PreconditionFailed));
}

#[test]
fn a_version_that_cannot_grow_is_an_internal_defect() {
    let invalid = EntityVersion::new(i64::MAX).unwrap().next().unwrap_err();

    let error = IamError::from(RoleChangeRefused::Invalid(invalid));

    assert!(matches!(error, IamError::Internal(_)));
}

#[test]
fn a_revoked_assignment_refusal_is_not_found() {
    let error = IamError::from(UserRoleChangeRefused::Revoked);

    assert!(matches!(error, IamError::NotFound));
}

#[test]
fn an_assignment_refusal_for_the_version_is_a_precondition_error() {
    let stale = VersionConflict::Stale {
        expected: EntityVersion::new(1).unwrap(),
        current: EntityVersion::new(2).unwrap(),
    };

    assert!(matches!(
        IamError::from(UserRoleChangeRefused::Version(VersionConflict::Missing)),
        IamError::PreconditionRequired
    ));
    assert!(matches!(
        IamError::from(UserRoleChangeRefused::Version(stale)),
        IamError::PreconditionFailed
    ));
}

#[test]
fn an_assignment_version_that_cannot_grow_is_an_internal_defect() {
    let invalid = EntityVersion::new(i64::MAX).unwrap().next().unwrap_err();

    let error = IamError::from(UserRoleChangeRefused::Range(invalid));

    assert!(matches!(error, IamError::Internal(_)));
}

#[test]
fn an_expiry_that_is_not_in_the_future_is_one_violation_of_expires_at() {
    let error = IamError::from(UserRoleChangeRefused::Invalid(
        InvalidUserRole::ExpiryNotInFuture,
    ));

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "expiresAt");
    assert_eq!(violations[0].code, "future");
}

#[test]
fn an_invalid_specification_is_one_violation_of_its_property_with_its_position() {
    use iam_domain::{InvalidSpec, SpecPosition};

    let error = IamError::from(InvalidSpec::Malformed {
        message: "unexpected token".to_owned(),
        position: SpecPosition::LineColumn { line: 3, column: 7 },
    });
    let problem = Problem::from(error);

    assert_eq!(problem.status, 422);
    assert_eq!(
        problem.violations,
        vec![Violation {
            property_path: "sdl".to_owned(),
            message: "unexpected token (line 3, column 7)".to_owned(),
            code: "syntax".to_owned(),
        }]
    );
}

#[rstest]
#[case(
    Confirmation::FlagDowngrade,
    TYPE_FLAG_DOWNGRADE_CONFIRMATION,
    "confirmFlagDowngrade"
)]
#[case(Confirmation::Orphans, TYPE_ORPHAN_CONFIRMATION, "confirmOrphans")]
fn a_missing_confirmation_is_the_409_problem_that_lists_what_it_affects(
    #[case] confirmation: Confirmation,
    #[case] problem_type: &str,
    #[case] flag: &str,
) {
    let (recorder, _guard) = LogRecorder::install();
    let item = Violation {
        property_path: "gql:billing:Mutation.pay".to_owned(),
        message: "This key is affected.".to_owned(),
        code: "affected".to_owned(),
    };

    let problem = Problem::from(IamError::ConfirmationRequired(
        confirmation,
        vec![item.clone()],
    ));

    assert_eq!(problem.status, 409);
    assert_eq!(problem.title, "Conflict");
    assert_eq!(problem.r#type, problem_type);
    assert_eq!(confirmation.problem_type(), problem_type);
    assert!(problem.detail.as_deref().unwrap().contains(flag));
    assert_eq!(problem.violations, vec![item]);
    assert_eq!(recorder.lines().len(), 0);
}

#[test]
fn the_message_of_a_missing_confirmation_is_fixed() {
    assert_eq!(
        IamError::ConfirmationRequired(Confirmation::Orphans, Vec::new()).to_string(),
        "The change needs a confirmation."
    );
}

#[test]
fn an_invalid_catalogue_statement_is_an_internal_failure_that_names_its_cause() {
    let invalid = InvalidCatalogueEntry::OutsideService {
        key: "gql:other:Query.bills".to_owned(),
    };
    let cause = invalid.to_string();

    let error = IamError::from(invalid);

    assert!(matches!(error, IamError::Internal(_)));
    assert_eq!(error.source().map(ToString::to_string), Some(cause));
}
