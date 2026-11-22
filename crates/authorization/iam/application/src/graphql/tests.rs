use async_graphql::Value;
use axum::http::StatusCode;
use iam_domain::EntityVersion;
use rstest::rstest;
use shared_application::http::{Problem, Violation};

use super::{IamMutation, IamQuery, expected_version, iam_problem_to_graphql_error};
use crate::error::IamError;

fn default_of<T: Default>() -> T {
    T::default()
}

fn code(error: &async_graphql::Error) -> Option<Value> {
    error
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

#[test]
fn the_roots_are_default_and_debug_like_every_root_the_schema_merges() {
    assert_eq!(format!("{:?}", default_of::<IamQuery>()), "IamQuery");
    assert_eq!(format!("{:?}", default_of::<IamMutation>()), "IamMutation");
}

#[rstest]
#[case::unauthenticated(
    IamError::Unauthenticated,
    401,
    "UNAUTHENTICATED",
    "A valid bearer token is required."
)]
#[case::not_found(
    IamError::NotFound,
    404,
    "NOT_FOUND",
    "The requested IAM record was not found."
)]
#[case::conflict(
    IamError::Conflict,
    409,
    "CONFLICT",
    "The IAM record conflicts with its current state."
)]
#[case::idempotency_mismatch(
    IamError::IdempotencyMismatch,
    422,
    "VALIDATION_FAILED",
    "The idempotency key was already used for a different request."
)]
#[case::precondition_required(
    IamError::PreconditionRequired,
    428,
    "PRECONDITION_REQUIRED",
    "The request must name the version it changes."
)]
#[case::precondition_failed(
    IamError::PreconditionFailed,
    412,
    "PRECONDITION_FAILED",
    "The request names a version that is not the current version."
)]
#[case::storage(
    IamError::Storage("disk on fire".into()),
    500,
    "INTERNAL_SERVER_ERROR",
    "Internal server error"
)]
fn each_variant_has_the_status_and_the_code_of_the_error_table(
    #[case] error: IamError,
    #[case] status: u16,
    #[case] expected_code: &str,
    #[case] message: &str,
) {
    let problem = Problem::from(error);
    assert_eq!(problem.status, status);

    let graphql = iam_problem_to_graphql_error(problem);

    assert_eq!(code(&graphql), Some(code_of(expected_code)));
    assert_eq!(graphql.message, message);
}

#[rstest]
#[case::unauthenticated(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED")]
#[case::forbidden(StatusCode::FORBIDDEN, "FORBIDDEN")]
#[case::dependency_unavailable(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")]
#[case::query_timeout(StatusCode::GATEWAY_TIMEOUT, "QUERY_TIMEOUT")]
fn the_other_statuses_of_the_error_table_have_their_codes(
    #[case] status: StatusCode,
    #[case] expected_code: &str,
) {
    let problem = Problem::new(status).with_detail("details of the failure");

    let graphql = iam_problem_to_graphql_error(problem);

    assert_eq!(code(&graphql), Some(code_of(expected_code)));
    assert_eq!(graphql.message, "details of the failure");
}

#[test]
fn a_client_error_without_detail_falls_back_to_its_title() {
    let graphql = iam_problem_to_graphql_error(Problem::new(StatusCode::NOT_FOUND));

    assert_eq!(code(&graphql), Some(code_of("NOT_FOUND")));
    assert_eq!(graphql.message, "Not Found");
}

#[test]
fn a_validation_problem_keeps_its_violations() {
    let problem = Problem::validation_failed(vec![Violation {
        property_path: "idempotencyKey".to_owned(),
        message: "invalid".to_owned(),
        code: "format".to_owned(),
    }]);

    let graphql = iam_problem_to_graphql_error(problem);

    assert_eq!(code(&graphql), Some(code_of("VALIDATION_FAILED")));
    let violations = graphql
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("violations"))
        .cloned();
    assert!(matches!(violations, Some(Value::List(list)) if list.len() == 1));
}

#[test]
fn an_input_without_expected_version_is_the_required_precondition() {
    let error = expected_version(None).unwrap_err();

    assert!(matches!(error, IamError::PreconditionRequired));
    let graphql = iam_problem_to_graphql_error(Problem::from(error));
    assert_eq!(code(&graphql), Some(code_of("PRECONDITION_REQUIRED")));
}

#[rstest]
#[case::zero(0)]
#[case::negative(-3)]
fn an_expected_version_below_one_is_the_failed_precondition(#[case] field: i64) {
    let error = expected_version(Some(field)).unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    let graphql = iam_problem_to_graphql_error(Problem::from(error));
    assert_eq!(code(&graphql), Some(code_of("PRECONDITION_FAILED")));
}

#[rstest]
#[case::one(1)]
#[case::largest(i64::MAX)]
fn an_expected_version_is_its_entity_version(#[case] field: i64) {
    assert_eq!(
        expected_version(Some(field)).unwrap(),
        EntityVersion::new(field).unwrap()
    );
}
