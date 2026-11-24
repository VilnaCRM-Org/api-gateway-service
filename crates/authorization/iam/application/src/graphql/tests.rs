use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_graphql::{EmptyMutation, EmptySubscription, Request, Schema, Value, Variables};
use axum::http::StatusCode;
use iam_domain::{
    AccessToken, AccessTokenParts, EntityVersion, SessionId, SubjectId, TokenId, TokenIdentity,
    TokenRejection,
};
use rstest::rstest;
use serde_json::json;
use shared_application::http::{Problem, Violation};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use super::{
    IamMutation, IamQuery, ResolveTokenInput, expected_version, iam_problem_to_graphql_error,
};
use crate::error::{Confirmation, IamError};
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::resolve_subject_token::{ResolveSubjectTokenQuery, TokenResolution};

mod revocation_reads;
mod role_deletion;
mod roles;
mod route_configurations;
mod routes;
mod security_audit_events;
mod upstreams;
mod user_roles;

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
fn a_confirmation_problem_keeps_the_items_it_lists() {
    let problem = Problem::from(IamError::ConfirmationRequired(
        Confirmation::Orphans,
        vec![Violation {
            property_path: "gql:billing:Query.invoices".to_owned(),
            message: "the grant of role Payer becomes inactive".to_owned(),
            code: "orphaned".to_owned(),
        }],
    ));

    let graphql = iam_problem_to_graphql_error(problem);

    assert_eq!(
        code(&graphql),
        Some(code_of("ORPHAN_CONFIRMATION_REQUIRED"))
    );
    let violations = graphql
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("violations"))
        .cloned();
    let Some(Value::List(list)) = violations else {
        panic!("the listed items expected: {violations:?}");
    };
    assert_eq!(list.len(), 1);
    assert!(list[0].to_string().contains("gql:billing:Query.invoices"));
}

#[test]
fn a_client_error_without_items_has_no_violations() {
    let graphql = iam_problem_to_graphql_error(Problem::new(StatusCode::CONFLICT));

    assert_eq!(code(&graphql), Some(code_of("CONFLICT")));
    assert!(
        graphql
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("violations"))
            .is_none()
    );
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

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn state(queries: FakeQueryBus) -> IamState {
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> = Arc::new(queries);
    IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    }
}

fn resolving(resolution: TokenResolution) -> FakeQueryBus {
    FakeQueryBus::answering(move |_query: ResolveSubjectTokenQuery| Ok(resolution.clone()))
}

const QUERY: &str = "query($credential: String!) { resolveToken(input: { credential: $credential }) \
    { resolved reason subjectId subjectKind sessionId roles expiresAt } }";

type IamSchema = Schema<IamQuery, EmptyMutation, EmptySubscription>;

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, EmptyMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Data(Option<Principal>),
}

async fn run(schema: &IamSchema, caller: Caller, credential: &str) -> async_graphql::Response {
    let variables = Variables::from_json(json!({ "credential": credential }));
    let mut request = Request::new(QUERY).variables(variables);
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    schema.execute(request).await
}

fn error_code(response: &async_graphql::Response) -> Option<Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

#[tokio::test]
async fn an_authenticated_caller_resolves_a_valid_credential_into_its_subject() {
    let state = state(resolving(TokenResolution::Resolved(principal())));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        "raw-secret-token",
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "resolveToken": {
            "resolved": true,
            "reason": null,
            "subjectId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
            "subjectKind": "user",
            "sessionId": "session-1",
            "roles": ["ROLE_USER"],
            "expiresAt": 900,
        } })
    );
}

#[tokio::test]
async fn a_refused_credential_is_data_with_its_reason_code() {
    let refused = TokenResolution::Unresolved(TokenRejection::Revoked);
    let state = state(resolving(refused));

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), "bad").await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "resolveToken": {
            "resolved": false,
            "reason": "token_revoked",
            "subjectId": null,
            "subjectKind": null,
            "sessionId": null,
            "roles": null,
            "expiresAt": null,
        } })
    );
}

#[rstest]
#[case::refused_caller(Caller::Data(None))]
#[case::no_caller_data(Caller::Absent)]
#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated(#[case] caller: Caller) {
    let state = state(resolving(TokenResolution::Resolved(principal())));

    let response = run(&schema(Some(state)), caller, "token").await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
}

#[tokio::test]
async fn a_credential_above_the_length_limit_is_a_validation_failure() {
    let state = state(resolving(TokenResolution::Resolved(principal())));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        &"a".repeat(8193),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn an_unreadable_revocation_state_is_an_internal_error() {
    let failing = FakeQueryBus::answering(|_query: ResolveSubjectTokenQuery| {
        Err::<TokenResolution, _>(IamError::Storage("disk on fire".into()))
    });

    let response = run(
        &schema(Some(state(failing))),
        Caller::Data(Some(principal())),
        "token",
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
    assert!(!format!("{:?}", response.errors).contains("disk on fire"));
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Data(Some(principal())), "token").await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_input_never_prints_the_credential() {
    let input = ResolveTokenInput {
        credential: "raw-secret-token".to_owned(),
    };

    let printed = format!("{input:?}");

    assert!(printed.starts_with("ResolveTokenInput"), "{printed}");
    assert!(!printed.contains("raw-secret-token"), "{printed}");
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let object = Value::Object(
        std::iter::once((Name::new("credential"), Value::String("token".to_owned()))).collect(),
    );

    let parsed = ResolveTokenInput::parse(Some(object)).unwrap();

    assert_eq!(parsed.credential, "token");
    assert!(ResolveTokenInput::parse(Some(Value::Boolean(true))).is_err());
    let wrong_type =
        Value::Object(std::iter::once((Name::new("credential"), Value::Boolean(true))).collect());
    assert!(ResolveTokenInput::parse(Some(wrong_type)).is_err());
}
