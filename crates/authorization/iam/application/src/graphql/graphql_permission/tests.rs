use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{GqlName, PermissionId, ServiceName};
use serde_json::json;

use super::{GraphQlPermissionFilterInput, GraphQlPermissionObject, GraphQlPermissionPageObject};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::graphql_permission_fixtures::{
    Answers, PERMISSION, ROLE, VERSION, recorded, scenario, view_of,
};
use crate::http::IamState;
use crate::http::graphql_permission::dto::{
    GraphQlPermissionPageResponse, GraphQlPermissionResponse,
};
use crate::principal::Principal;
use crate::query::get_graphql_permission::GetGraphQlPermissionQuery;
use crate::query::get_graphql_permissions::{GetGraphQlPermissionsQuery, GraphQlPermissionPage};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const LIST: &str = "query($first: Int, $after: String, $filter: GraphqlPermissionFilter) \
    { graphqlPermissions(first: $first, after: $after, filter: $filter) \
    { items { id key service type field flags { sensitive auditAlways } active versions roles } \
    nextCursor } }";

const ONE: &str = "query($id: ID!) \
    { graphqlPermission(id: $id) { id key type field active versions roles } }";

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

async fn read(
    schema: &IamSchema,
    caller: Caller,
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
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

fn permission_id() -> PermissionId {
    PermissionId::parse(PERMISSION).unwrap()
}

#[tokio::test]
async fn the_list_is_a_page_of_entries_with_the_cursor_of_the_next_page() {
    let (state, asked) = scenario(Answers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlPermissions": {
            "items": [{
                "id": PERMISSION,
                "key": "gql:billing:Mutation.pay",
                "service": "billing",
                "type": "Mutation",
                "field": "pay",
                "flags": { "sensitive": true, "auditAlways": false },
                "active": true,
                "versions": [VERSION],
                "roles": [ROLE],
            }],
            "nextCursor": PERMISSION,
        } })
    );
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlPermissionsQuery {
            limit: 30,
            after: None,
            service: None,
            type_name: None,
            active: None,
            sensitive: None,
            key_prefix: None,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_its_arguments_to_the_query() {
    let (state, asked) = scenario(Answers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({
            "first": 5,
            "after": PERMISSION,
            "filter": {
                "service": "billing",
                "type": "Mutation",
                "active": true,
                "sensitive": false,
                "keyPrefix": "gql:billing:Mutation.",
            },
        }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlPermissionsQuery {
            limit: 5,
            after: Some(permission_id()),
            service: Some(ServiceName::new("billing").unwrap()),
            type_name: Some(GqlName::parse("Mutation").unwrap()),
            active: Some(true),
            sensitive: Some(false),
            key_prefix: Some("gql:billing:Mutation.".to_owned()),
        }]
    );
}

#[tokio::test]
async fn the_last_page_has_a_null_cursor() {
    let answers = Answers {
        page: Ok(GraphQlPermissionPage {
            permissions: Vec::new(),
            next_after: None,
        }),
        ..Answers::default()
    };
    let (state, _asked) = scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({}),
    )
    .await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlPermissions": { "items": [], "nextCursor": null } })
    );
}

#[tokio::test]
async fn an_invalid_list_argument_is_a_failed_validation_and_asks_nothing() {
    for variables in [
        json!({ "first": 0 }),
        json!({ "first": 101 }),
        json!({ "after": "nope" }),
        json!({ "filter": { "service": "Not A Service" } }),
        json!({ "filter": { "type": "1Bad" } }),
    ] {
        let (state, asked) = scenario(Answers::default());

        let response = read(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            LIST,
            variables,
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
        assert_eq!(
            recorded(&asked.pages),
            Vec::<GetGraphQlPermissionsQuery>::new()
        );
    }
}

#[tokio::test]
async fn one_entry_is_read_by_id() {
    let (state, asked) = scenario(Answers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": PERMISSION }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlPermission": {
            "id": PERMISSION,
            "key": "gql:billing:Mutation.pay",
            "type": "Mutation",
            "field": "pay",
            "active": true,
            "versions": [VERSION],
            "roles": [ROLE],
        } })
    );
    assert_eq!(
        recorded(&asked.ones),
        [GetGraphQlPermissionQuery {
            id: permission_id()
        }]
    );
}

#[tokio::test]
async fn an_unknown_entry_is_null() {
    let answers = Answers {
        one: Ok(None),
        ..Answers::default()
    };
    let (state, _asked) = scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": PERMISSION }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlPermission": null })
    );
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_failed_validation() {
    let (state, asked) = scenario(Answers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": "not-a-uuid" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(
        recorded(&asked.ones),
        Vec::<GetGraphQlPermissionQuery>::new()
    );
}

#[tokio::test]
async fn a_caller_that_the_authentication_refused_or_none_is_unauthenticated() {
    for (caller, query, variables) in [
        (Caller::Absent, LIST, json!({})),
        (Caller::Data(None), LIST, json!({})),
        (Caller::Absent, ONE, json!({ "id": PERMISSION })),
        (Caller::Data(None), ONE, json!({ "id": PERMISSION })),
    ] {
        let (state, asked) = scenario(Answers::default());

        let response = read(&schema(Some(state)), caller, query, variables).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert_eq!(
            recorded(&asked.pages),
            Vec::<GetGraphQlPermissionsQuery>::new()
        );
        assert_eq!(
            recorded(&asked.ones),
            Vec::<GetGraphQlPermissionQuery>::new()
        );
    }
}

#[tokio::test]
async fn a_schema_without_the_iam_state_is_an_internal_error() {
    for (query, variables) in [(LIST, json!({})), (ONE, json!({ "id": PERMISSION }))] {
        let response = read(
            &schema(None),
            Caller::Data(Some(principal())),
            query,
            variables,
        )
        .await;

        assert_eq!(
            error_code(&response),
            Some(code_of("INTERNAL_SERVER_ERROR"))
        );
    }
}

#[tokio::test]
async fn a_storage_failure_is_an_internal_error() {
    for (answers, query, variables) in [
        (
            Answers {
                page: Err(|| IamError::Storage("down".into())),
                ..Answers::default()
            },
            LIST,
            json!({}),
        ),
        (
            Answers {
                one: Err(|| IamError::Storage("down".into())),
                ..Answers::default()
            },
            ONE,
            json!({ "id": PERMISSION }),
        ),
    ] {
        let (state, _asked) = scenario(answers);

        let response = read(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            query,
            variables,
        )
        .await;

        assert_eq!(
            error_code(&response),
            Some(code_of("INTERNAL_SERVER_ERROR"))
        );
    }
}

#[test]
fn the_objects_are_the_rest_responses_in_graphql_form() {
    let response = GraphQlPermissionResponse::from(view_of("gql:billing:__introspection"));
    let object = GraphQlPermissionObject::from(response.clone());
    let page = GraphQlPermissionPageObject::from(GraphQlPermissionPageResponse {
        items: vec![response],
        next_cursor: None,
    });

    assert_eq!(object.type_of, "__introspection");
    assert!(object.flags.sensitive);
    assert_eq!(page.items, [object]);
    assert_eq!(page.next_cursor, None);
    assert!(GraphQlPermissionFilterInput::default().service.is_none());
}

#[test]
fn the_filter_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let filter = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };

    let parsed = GraphQlPermissionFilterInput::parse(Some(filter(vec![
        ("service", Value::String("billing".to_owned())),
        ("type", Value::String("Mutation".to_owned())),
        ("active", Value::Boolean(true)),
        ("sensitive", Value::Boolean(false)),
        ("keyPrefix", Value::String("gql:billing:".to_owned())),
    ])))
    .unwrap();

    assert_eq!(parsed.service.as_deref(), Some("billing"));
    assert_eq!(parsed.type_name.as_deref(), Some("Mutation"));
    assert_eq!(parsed.active, Some(true));
    assert_eq!(parsed.sensitive, Some(false));
    assert_eq!(parsed.key_prefix.as_deref(), Some("gql:billing:"));
    assert!(GraphQlPermissionFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["service", "type", "active", "sensitive", "keyPrefix"] {
        let wrong = filter(vec![(field, Value::List(Vec::new()))]);
        assert!(
            GraphQlPermissionFilterInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
