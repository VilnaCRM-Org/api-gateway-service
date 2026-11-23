use async_graphql::{EmptySubscription, InputType as _, Name, Request, Schema, Value, Variables};
use iam_domain::{ActorRef, RoleId};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;

use crate::error::IamError;
use crate::fixtures::{Answers, ROLE, USER, principal, receipt_at, recorded, scenario};
use crate::graphql::role_deletion::{DeleteRoleInput, DeleteRolePayload};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const DELETE: &str = "mutation($input: DeleteRoleInput!) { deleteRole(input: $input) \
    { id version policyVersion revokedAssignments } }";

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, IamMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Refused,
    Valid,
}

async fn run(
    schema: &IamSchema,
    caller: Caller,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(DELETE).variables(Variables::from_json(variables));
    match caller {
        Caller::Absent => {}
        Caller::Refused => request = request.data(None::<Principal>),
        Caller::Valid => request = request.data(Some(principal())),
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

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

fn deleted(revoked: u32) -> Answers {
    Answers {
        receipt: receipt_at(2, Some(5)).with_revoked_assignments(revoked),
        ..Answers::default()
    }
}

fn deletion(expected: Option<i64>) -> serde_json::Value {
    json!({ "input": { "id": ROLE, "expectedVersion": expected } })
}

#[tokio::test]
async fn a_deleted_role_reports_the_revoked_assignments_and_dispatches_the_command() {
    let (state, commands, queries, asked) = scenario(deleted(3));

    let response = run(&schema(Some(state)), Caller::Valid, deletion(Some(1))).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteRole": {
            "id": ROLE,
            "version": 2,
            "policyVersion": 5,
            "revokedAssignments": 3,
        } })
    );
    assert_eq!(commands.dispatched(), ["DeleteRoleCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_receipt_without_a_count_reports_no_revoked_assignments() {
    let answers = Answers {
        receipt: receipt_at(2, None),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(&schema(Some(state)), Caller::Valid, deletion(Some(1))).await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteRole": {
            "id": ROLE,
            "version": 2,
            "policyVersion": null,
            "revokedAssignments": 0,
        } })
    );
}

#[test]
fn a_count_above_the_graphql_integer_range_is_clamped() {
    let receipt = receipt_at(2, None).with_revoked_assignments(u32::MAX);

    assert_eq!(
        DeleteRolePayload::from(&receipt).revoked_assignments,
        i32::MAX
    );
}

#[rstest]
#[case::absent(json!({ "input": { "id": ROLE } }))]
#[case::null(json!({ "input": { "id": ROLE, "expectedVersion": null } }))]
#[tokio::test]
async fn a_deletion_without_a_version_is_precondition_required(
    #[case] variables: serde_json::Value,
) {
    let (state, commands, _queries, _asked) = scenario(deleted(0));

    let response = run(&schema(Some(state)), Caller::Valid, variables).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("PRECONDITION_REQUIRED"))
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_version_below_one_is_a_failed_precondition() {
    let (state, commands, _queries, _asked) = scenario(deleted(0));

    let response = run(&schema(Some(state)), Caller::Valid, deletion(Some(0))).await;

    assert_eq!(error_code(&response), Some(code_of("PRECONDITION_FAILED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(Answers { delete: Err(|| IamError::PreconditionFailed), ..deleted(0) }, "PRECONDITION_FAILED")]
#[case::system_role(Answers { delete: Err(|| IamError::Forbidden), ..deleted(0) }, "FORBIDDEN")]
#[case::unknown(Answers { delete: Err(|| IamError::NotFound), ..deleted(0) }, "NOT_FOUND")]
#[case::concurrent(Answers { delete: Err(|| IamError::Conflict), ..deleted(0) }, "CONFLICT")]
#[case::mismatch(
    Answers { replay: Err(|| IamError::IdempotencyMismatch), ..deleted(0) },
    "VALIDATION_FAILED"
)]
#[case::storage(
    Answers { delete: Err(|| IamError::Storage("disk on fire".into())), ..deleted(0) },
    "INTERNAL_SERVER_ERROR"
)]
#[tokio::test]
async fn a_refused_deletion_has_the_code_of_its_error(
    #[case] answers: Answers,
    #[case] expected: &str,
) {
    let (state, _commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": { "id": ROLE, "expectedVersion": 1, "idempotencyKey": "k" } });

    let response = run(&schema(Some(state)), Caller::Valid, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[rstest]
#[case::bad_key(json!({ "idempotencyKey": "not valid" }), "\"idempotencyKey\"")]
#[case::bad_id(json!({ "id": "nope" }), "\"id\"")]
#[tokio::test]
async fn an_invalid_field_is_a_validation_failure_with_its_violation(
    #[case] fields: serde_json::Value,
    #[case] property: &str,
) {
    let (state, commands, _queries, _asked) = scenario(deleted(0));
    let mut input = json!({ "id": ROLE, "expectedVersion": 1 });
    input
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    let paths = response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("violations"))
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(paths.contains(property), "{paths}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_replayed_deletion_returns_the_original_count_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, Some(7)).with_revoked_assignments(3))),
        ..deleted(0)
    };
    let (state, commands, _queries, _asked) = scenario(answers);
    let variables =
        json!({ "input": { "id": ROLE, "expectedVersion": 1, "idempotencyKey": "delete" } });

    let response = run(&schema(Some(state)), Caller::Valid, variables).await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteRole": {
            "id": ROLE,
            "version": 2,
            "policyVersion": 7,
            "revokedAssignments": 3,
        } })
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::refused(Caller::Refused)]
#[case::absent(Caller::Absent)]
#[tokio::test]
async fn a_deletion_needs_an_authenticated_caller(#[case] caller: Caller) {
    let (state, commands, _queries, _asked) = scenario(deleted(0));

    let response = run(&schema(Some(state)), caller, deletion(Some(1))).await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, deletion(Some(1))).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_deletion_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    let object = Value::Object(
        [
            (Name::new("id"), Value::String(ROLE.to_owned())),
            (Name::new("expectedVersion"), Value::Number(3.into())),
            (Name::new("idempotencyKey"), Value::String("k".to_owned())),
        ]
        .into_iter()
        .collect(),
    );

    let parsed = DeleteRoleInput::parse(Some(object)).unwrap();

    assert_eq!(parsed.id.as_str(), ROLE);
    assert_eq!(parsed.expected_version, Some(3));
    assert_eq!(parsed.idempotency_key.as_deref(), Some("k"));
    assert!(DeleteRoleInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["id", "expectedVersion", "idempotencyKey"] {
        let wrong = Value::Object(
            [
                (Name::new("id"), Value::String(ROLE.to_owned())),
                (Name::new(field), Value::List(Vec::new())),
            ]
            .into_iter()
            .collect(),
        );
        assert!(DeleteRoleInput::parse(Some(wrong)).is_err(), "{field}");
    }
}
