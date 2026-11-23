use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use serde_json::json;
use shared_application::http::Violation;

use crate::error::{Confirmation, IamError};
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::openapi_spec_fixtures::SPEC;
use crate::principal::Principal;
use crate::rest_activation_fixtures::{
    Answers, CREATED, active_summary, receipt, recorded, scenario,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const ACTIVATE: &str = "mutation($input: CreateRestPermissionsInput!) { \
    createRestPermissions(input: $input) { id service status createdKeys policyVersion } }";

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
    Data(Option<Principal>),
}

async fn run(
    schema: &IamSchema,
    caller: Caller,
    input: serde_json::Value,
) -> async_graphql::Response {
    let mut request =
        Request::new(ACTIVATE).variables(Variables::from_json(json!({ "input": input })));
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

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

#[tokio::test]
async fn an_activation_returns_the_same_data_as_over_rest() {
    let (state, commands) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "createRestPermissions": {
            "id": SPEC,
            "service": "billing",
            "status": "active",
            "createdKeys": [CREATED],
            "policyVersion": 7,
        } })
    );
    let dispatched = recorded(&commands);
    assert_eq!(dispatched.len(), 1);
    assert!(!dispatched[0].confirm_orphans);
    assert!(!dispatched[0].confirm_flag_downgrade);
    assert_eq!(
        dispatched[0].renames,
        Vec::<(iam_domain::PermissionKey, iam_domain::PermissionKey)>::new()
    );
    assert!(dispatched[0].idempotency.is_none());
}

#[tokio::test]
async fn the_confirmations_the_renames_and_the_idempotency_key_reach_the_command() {
    let (state, commands) = scenario(Answers::default());
    let input = json!({
        "id": SPEC,
        "confirmOrphans": true,
        "confirmFlagDowngrade": true,
        "renames": [{ "from": "rest:billing:GET /bills", "to": CREATED }],
        "idempotencyKey": "activate-1",
    });

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let dispatched = recorded(&commands);
    assert!(dispatched[0].confirm_orphans);
    assert!(dispatched[0].confirm_flag_downgrade);
    assert_eq!(dispatched[0].renames.len(), 1);
    assert_eq!(
        dispatched[0].idempotency.as_ref().unwrap().key.as_str(),
        "activate-1"
    );
}

#[tokio::test]
async fn an_active_version_is_a_no_op_with_no_created_keys() {
    let (state, commands) = scenario(Answers {
        spec: Ok(Some(active_summary())),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["createRestPermissions"]["createdKeys"], json!([]));
    assert_eq!(data["createRestPermissions"]["policyVersion"], json!(0));
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn a_replayed_key_returns_the_original_result_without_a_command() {
    let (state, commands) = scenario(Answers {
        replay: Some(receipt(Some(5))),
        ..Answers::default()
    });
    let input = json!({ "id": SPEC, "idempotencyKey": "activate-1" });

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["createRestPermissions"]["policyVersion"], json!(5));
    assert!(recorded(&commands).is_empty());
}

fn needs_flag_confirmation() -> IamError {
    IamError::ConfirmationRequired(
        Confirmation::FlagDowngrade,
        vec![Violation {
            property_path: "rest:billing:POST /invoices/{}/pay".to_owned(),
            message: "This key would lose a flag.".to_owned(),
            code: "flag_downgrade".to_owned(),
        }],
    )
}

fn needs_orphan_confirmation() -> IamError {
    IamError::ConfirmationRequired(Confirmation::Orphans, Vec::new())
}

#[tokio::test]
async fn a_missing_flag_confirmation_is_its_own_error_code() {
    let (state, _commands) = scenario(Answers {
        command: Err(needs_flag_confirmation),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("FLAG_DOWNGRADE_CONFIRMATION_REQUIRED"))
    );
}

#[tokio::test]
async fn a_missing_orphan_confirmation_is_its_own_error_code() {
    let (state, _commands) = scenario(Answers {
        command: Err(needs_orphan_confirmation),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("ORPHAN_CONFIRMATION_REQUIRED"))
    );
}

#[tokio::test]
async fn any_other_conflict_keeps_the_conflict_code() {
    let (state, _commands) = scenario(Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("CONFLICT")));
}

#[tokio::test]
async fn an_unknown_version_is_not_found() {
    let (state, _commands) = scenario(Answers {
        spec: Ok(None),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("NOT_FOUND")));
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_a_validation_failure() {
    let (state, _commands) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": "nope" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_a_validation_failure() {
    let (state, _commands) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC, "idempotencyKey": "" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_rename_that_is_not_a_key_is_a_validation_failure() {
    let (state, commands) = scenario(Answers::default());
    let input = json!({ "id": SPEC, "renames": [{ "from": "nonsense", "to": CREATED }] });

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&commands).is_empty());
}

#[tokio::test]
async fn a_rename_with_an_empty_key_is_a_validation_failure() {
    let (state, _commands) = scenario(Answers::default());
    let input = json!({ "id": SPEC, "renames": [{ "from": "", "to": CREATED }] });

    let response = run(&schema(Some(state)), Caller::Data(Some(principal())), input).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_request_without_an_authenticated_caller_is_unauthenticated() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, _commands) = scenario(Answers::default());

        let response = run(&schema(Some(state)), caller, json!({ "id": SPEC })).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_activation_inputs_print_their_fields() {
    let input = super::CreateRestPermissionsInput {
        id: async_graphql::ID::from(SPEC),
        confirm_orphans: true,
        confirm_flag_downgrade: false,
        renames: vec![super::KeyRenameInput {
            from: "rest:billing:GET /bills".to_owned(),
            to: "rest:billing:GET /invoices".to_owned(),
        }],
        idempotency_key: None,
    };

    assert_eq!(
        format!("{input:?}"),
        format!(
            "CreateRestPermissionsInput {{ id: ID(\"{SPEC}\"), confirm_orphans: true, \
             confirm_flag_downgrade: false, renames: [KeyRenameInput {{ from: \
             \"rest:billing:GET /bills\", to: \"rest:billing:GET /invoices\" }}], \
             idempotency_key: None }}"
        )
    );
}

#[test]
fn the_activation_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::{InputType as _, Name};

    let rename = Value::Object(
        [
            (
                Name::new("from"),
                Value::String("rest:billing:GET /bills".to_owned()),
            ),
            (
                Name::new("to"),
                Value::String("rest:billing:GET /invoices".to_owned()),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let input = Value::Object(
        [
            (Name::new("id"), Value::String(SPEC.to_owned())),
            (Name::new("confirmOrphans"), Value::Boolean(true)),
            (Name::new("renames"), Value::List(vec![rename])),
        ]
        .into_iter()
        .collect(),
    );

    let parsed = super::CreateRestPermissionsInput::parse(Some(input)).unwrap();

    assert_eq!(parsed.id.as_str(), SPEC);
    assert!(parsed.confirm_orphans);
    assert!(!parsed.confirm_flag_downgrade);
    assert_eq!(parsed.renames.len(), 1);
    assert_eq!(parsed.renames[0].to, "rest:billing:GET /invoices");
    assert_eq!(parsed.idempotency_key, None);
    assert!(super::CreateRestPermissionsInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(super::KeyRenameInput::parse(Some(Value::Boolean(true))).is_err());
    for field in [
        "id",
        "confirmOrphans",
        "confirmFlagDowngrade",
        "renames",
        "idempotencyKey",
    ] {
        let wrong = Value::Object(
            [
                (Name::new("id"), Value::String(SPEC.to_owned())),
                (Name::new(field), Value::Enum(Name::new("WRONG"))),
            ]
            .into_iter()
            .collect(),
        );
        assert!(
            super::CreateRestPermissionsInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
    for field in ["from", "to"] {
        let wrong = Value::Object(
            [
                (
                    Name::new("from"),
                    Value::String("rest:billing:GET /bills".to_owned()),
                ),
                (
                    Name::new("to"),
                    Value::String("rest:billing:GET /invoices".to_owned()),
                ),
                (Name::new(field), Value::Boolean(true)),
            ]
            .into_iter()
            .collect(),
        );
        assert!(
            super::KeyRenameInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
