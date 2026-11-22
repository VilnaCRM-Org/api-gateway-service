use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{ActorRef, RoleId, RoleKind};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;

use crate::error::IamError;
use crate::fixtures::{Answers, ROLE, USER, principal, receipt, recorded, role, scenario};
use crate::graphql::{IamMutation, IamQuery, RoleObject, RolePageObject};
use crate::http::IamState;
use crate::http::dto::{RolePageResponse, RoleResponse};
use crate::principal::Principal;
use crate::query::list_roles::{ListRolesQuery, RolePage};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const CREATE: &str = "mutation($input: CreateRoleInput!) { createRole(input: $input) \
    { id name description kind grantCount version createdAt updatedAt } }";
const ROLE_BY_ID: &str = "query($id: ID!) { role(id: $id) { id name version } }";
const ROLES: &str = "query($first: Int, $after: String, $filter: RoleFilter) \
    { roles(first: $first, after: $after, filter: $filter) \
    { items { id name version } nextCursor } }";

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
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
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

fn violation_paths(response: &async_graphql::Response) -> Vec<String> {
    let violations = response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("violations"))
        .cloned();
    let Some(Value::List(list)) = violations else {
        return Vec::new();
    };
    list.into_iter()
        .filter_map(|violation| match violation {
            Value::Object(members) => members.get("propertyPath").map(ToString::to_string),
            Value::Null
            | Value::Number(_)
            | Value::String(_)
            | Value::Boolean(_)
            | Value::Binary(_)
            | Value::Enum(_)
            | Value::List(_) => None,
        })
        .collect()
}

fn created(name: &str) -> serde_json::Value {
    json!({ "input": { "name": name, "description": "Invoices" } })
}

#[tokio::test]
async fn a_created_role_returns_the_same_data_as_over_rest() {
    let (state, commands, _queries, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        CREATE,
        created("Billing"),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "createRole": {
            "id": ROLE,
            "name": "Billing",
            "description": "Invoices",
            "kind": "custom",
            "grantCount": 0,
            "version": 1,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:01:00.000000Z",
        } })
    );
    assert_eq!(commands.dispatched(), ["CreateRoleCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].name, "Billing");
    assert_eq!(sent[0].description.as_deref(), Some("Invoices"));
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn the_idempotency_key_of_the_input_travels_with_the_command() {
    let (state, _commands, queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": { "name": "Billing", "idempotencyKey": "create-billing" } });

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetRoleQuery"
        ]
    );
    let sent = recorded(&asked.commands);
    assert_eq!(
        sent[0]
            .idempotency
            .as_ref()
            .map(|request| request.key.as_str()),
        Some("create-billing")
    );
}

#[tokio::test]
async fn a_replayed_creation_returns_the_original_result_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt(None))),
        ..Answers::default()
    };
    let (state, commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": { "name": "Billing", "idempotencyKey": "create-billing" } });

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_invalid_idempotency_key_is_a_validation_failure_naming_the_key() {
    let (state, commands, _queries, _asked) = scenario(Answers::default());
    let variables = json!({ "input": { "name": "Billing", "idempotencyKey": "not valid" } });

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), ["\"idempotencyKey\""]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::empty_name(json!({ "input": { "name": "" } }), "\"name\"")]
#[case::long_description(
    json!({ "input": { "name": "a", "description": "d".repeat(1001) } }),
    "\"description\""
)]
#[tokio::test]
async fn an_invalid_field_is_a_validation_failure_with_its_violation(
    #[case] variables: serde_json::Value,
    #[case] property: &str,
) {
    let (state, commands, _queries, _asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_name_that_the_domain_refuses_is_a_validation_failure() {
    let answers = Answers {
        command: Err(|| IamError::from(vec![iam_domain::InvalidRole::NameControlCharacter])),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, created("a")).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[rstest]
#[case::conflict(Answers { command: Err(|| IamError::Conflict), ..Answers::default() }, "CONFLICT")]
#[case::mismatch(
    Answers { replay: Err(|| IamError::IdempotencyMismatch), ..Answers::default() },
    "VALIDATION_FAILED"
)]
#[case::storage(
    Answers { command: Err(|| IamError::Storage("disk on fire".into())), ..Answers::default() },
    "INTERNAL_SERVER_ERROR"
)]
#[tokio::test]
async fn a_refused_creation_has_the_code_of_its_error(
    #[case] answers: Answers,
    #[case] expected: &str,
) {
    let (state, _commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": { "name": "Billing", "idempotencyKey": "k" } });

    let response = run(&schema(Some(state)), Caller::Valid, CREATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[rstest]
#[case::refused(Caller::Refused)]
#[case::absent(Caller::Absent)]
#[tokio::test]
async fn every_role_field_needs_an_authenticated_caller(#[case] caller: Caller) {
    let (state, commands, queries, _asked) = scenario(Answers::default());
    let schema = schema(Some(state));

    let create = run(&schema, Caller::Absent, CREATE, created("Billing")).await;
    let read = run(&schema, caller, ROLE_BY_ID, json!({ "id": ROLE })).await;
    let list = run(&schema, Caller::Refused, ROLES, json!({})).await;

    for response in [create, read, list] {
        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    }
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_stored_role_is_read_by_id() {
    let answers = Answers {
        role: Ok(Some(role(3))),
        ..Answers::default()
    };
    let (state, _commands, _queries, asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ROLE_BY_ID,
        json!({ "id": ROLE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "role": { "id": ROLE, "name": "Billing", "version": 3 } })
    );
    assert_eq!(recorded(&asked.roles), [RoleId::parse(ROLE).unwrap()]);
}

#[tokio::test]
async fn an_unknown_role_is_null() {
    let answers = Answers {
        role: Ok(None),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ROLE_BY_ID,
        json!({ "id": ROLE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(response.data.into_json().unwrap(), json!({ "role": null }));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_validation_failure() {
    let (state, _commands, queries, _asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ROLE_BY_ID,
        json!({ "id": "x" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), ["\"id\""]);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_role_read_is_an_internal_error() {
    let answers = Answers {
        role: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ROLE_BY_ID,
        json!({ "id": ROLE }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn the_roles_field_defaults_to_the_first_page_of_thirty() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, ROLES, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "roles": { "items": [], "nextCursor": null } })
    );
    assert_eq!(
        recorded(&asked.lists),
        [ListRolesQuery {
            limit: 30,
            after: None,
            name_prefix: None,
            kind: None,
        }]
    );
}

#[tokio::test]
async fn the_roles_field_passes_its_arguments_and_answers_the_page_with_its_cursor() {
    let answers = Answers {
        page: Ok(RolePage {
            roles: vec![role(2)],
            next_after: Some(RoleId::parse(ROLE).unwrap()),
        }),
        ..Answers::default()
    };
    let (state, _commands, _queries, asked) = scenario(answers);
    let variables = json!({
        "first": 1,
        "after": ROLE,
        "filter": { "namePrefix": "bill", "kind": "system" },
    });

    let response = run(&schema(Some(state)), Caller::Valid, ROLES, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "roles": {
            "items": [{ "id": ROLE, "name": "Billing", "version": 2 }],
            "nextCursor": ROLE,
        } })
    );
    assert_eq!(
        recorded(&asked.lists),
        [ListRolesQuery {
            limit: 1,
            after: Some(RoleId::parse(ROLE).unwrap()),
            name_prefix: Some("bill".to_owned()),
            kind: Some(RoleKind::System),
        }]
    );
}

#[rstest]
#[case::zero(json!({ "first": 0 }), "\"limit\"")]
#[case::above(json!({ "first": 101 }), "\"limit\"")]
#[case::kind(json!({ "filter": { "kind": "owner" } }), "\"kind\"")]
#[case::cursor(json!({ "after": "x" }), "\"after\"")]
#[tokio::test]
async fn an_invalid_argument_is_a_validation_failure_with_its_violation(
    #[case] variables: serde_json::Value,
    #[case] property: &str,
) {
    let (state, _commands, queries, _asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, ROLES, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_list_is_an_internal_error() {
    let answers = Answers {
        page: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(&schema(Some(state)), Caller::Valid, ROLES, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error_for_every_role_field() {
    let schema = schema(None);

    let create = run(&schema, Caller::Valid, CREATE, created("Billing")).await;
    let read = run(&schema, Caller::Valid, ROLE_BY_ID, json!({ "id": ROLE })).await;
    let list = run(&schema, Caller::Valid, ROLES, json!({})).await;

    for response in [create, read, list] {
        assert_eq!(
            error_code(&response),
            Some(code_of("INTERNAL_SERVER_ERROR"))
        );
    }
}

#[test]
fn the_graphql_objects_carry_the_data_of_the_rest_responses() {
    let response = RoleResponse::from(role(2));
    let object = RoleObject::from(response.clone());

    assert_eq!(object.id.as_str(), ROLE);
    assert_eq!(object.name, response.name);
    assert_eq!(object.description, response.description);
    assert_eq!(object.kind, response.kind);
    assert_eq!(object.grant_count, response.grant_count);
    assert_eq!(object.version, 2);
    assert_eq!(object.created_at, response.created_at);
    assert_eq!(object.updated_at, response.updated_at);
    let page = RolePageObject::from(RolePageResponse::from(RolePage {
        roles: vec![role(2)],
        next_after: None,
    }));
    assert_eq!(page.items, [object]);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn the_role_inputs_print_their_fields() {
    let create = crate::graphql::CreateRoleInput {
        name: "Billing".to_owned(),
        description: None,
        idempotency_key: None,
    };
    let filter = crate::graphql::RoleFilterInput::default();

    assert_eq!(
        format!("{create:?}"),
        "CreateRoleInput { name: \"Billing\", description: None, idempotency_key: None }"
    );
    assert_eq!(
        format!("{filter:?}"),
        "RoleFilterInput { name_prefix: None, kind: None }"
    );
}

#[test]
fn the_role_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::{InputType as _, Name};

    let create = Value::Object(
        std::iter::once((Name::new("name"), Value::String("Billing".to_owned()))).collect(),
    );
    let filter = Value::Object(
        std::iter::once((Name::new("kind"), Value::String("custom".to_owned()))).collect(),
    );

    let parsed = crate::graphql::CreateRoleInput::parse(Some(create)).unwrap();
    let parsed_filter = crate::graphql::RoleFilterInput::parse(Some(filter)).unwrap();

    assert_eq!(parsed.name, "Billing");
    assert_eq!(parsed_filter.kind.as_deref(), Some("custom"));
    assert!(crate::graphql::CreateRoleInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(crate::graphql::RoleFilterInput::parse(Some(Value::Boolean(true))).is_err());
    let wrong_name =
        Value::Object(std::iter::once((Name::new("name"), Value::Boolean(true))).collect());
    let wrong_kind =
        Value::Object(std::iter::once((Name::new("kind"), Value::Boolean(true))).collect());
    assert!(crate::graphql::CreateRoleInput::parse(Some(wrong_name)).is_err());
    for field in ["description", "idempotencyKey"] {
        let wrong = Value::Object(
            [
                (Name::new("name"), Value::String("Billing".to_owned())),
                (Name::new(field), Value::Boolean(true)),
            ]
            .into_iter()
            .collect(),
        );
        assert!(
            crate::graphql::CreateRoleInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
    assert!(crate::graphql::RoleFilterInput::parse(Some(wrong_kind)).is_err());
}
