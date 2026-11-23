use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{HttpMethod, PermissionId, ServiceName};
use serde_json::json;

use super::{RestPermissionFilterInput, RestPermissionObject, RestPermissionPageObject};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::http::rest_permission::dto::{RestPermissionPageResponse, RestPermissionResponse};
use crate::principal::Principal;
use crate::query::get_rest_permission::GetRestPermissionQuery;
use crate::query::get_rest_permissions::{GetRestPermissionsQuery, RestPermissionPage};
use crate::rest_permission_fixtures::{
    Answers, PERMISSION, ROLE, VERSION, recorded, scenario, view_of,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const LIST: &str = "query($first: Int, $after: String, $filter: RestPermissionFilter) \
    { restPermissions(first: $first, after: $after, filter: $filter) \
    { items { id key service method template flags { sensitive auditAlways } active versions roles } \
    nextCursor } }";

const ONE: &str = "query($id: ID!) \
    { restPermission(id: $id) { id key method template active versions roles } }";

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
        json!({ "restPermissions": {
            "items": [{
                "id": PERMISSION,
                "key": "rest:billing:POST /api/invoices/{}/pay",
                "service": "billing",
                "method": "POST",
                "template": "/api/invoices/{}/pay",
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
        [GetRestPermissionsQuery {
            limit: 30,
            after: None,
            service: None,
            method: None,
            active: None,
            sensitive: None,
            template_prefix: None,
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
                "method": "POST",
                "active": true,
                "sensitive": false,
                "templatePrefix": "/api/invoices",
            },
        }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&asked.pages),
        [GetRestPermissionsQuery {
            limit: 5,
            after: Some(permission_id()),
            service: Some(ServiceName::new("billing").unwrap()),
            method: Some(HttpMethod::Post),
            active: Some(true),
            sensitive: Some(false),
            template_prefix: Some("/api/invoices".to_owned()),
        }]
    );
}

#[tokio::test]
async fn the_last_page_has_a_null_cursor() {
    let answers = Answers {
        page: Ok(RestPermissionPage {
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
        json!({ "restPermissions": { "items": [], "nextCursor": null } })
    );
}

#[tokio::test]
async fn an_invalid_list_argument_is_a_failed_validation_and_asks_nothing() {
    for variables in [
        json!({ "first": 0 }),
        json!({ "first": 101 }),
        json!({ "after": "nope" }),
        json!({ "filter": { "service": "Not A Service" } }),
        json!({ "filter": { "method": "get" } }),
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
            Vec::<GetRestPermissionsQuery>::new()
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
        json!({ "restPermission": {
            "id": PERMISSION,
            "key": "rest:billing:POST /api/invoices/{}/pay",
            "method": "POST",
            "template": "/api/invoices/{}/pay",
            "active": true,
            "versions": [VERSION],
            "roles": [ROLE],
        } })
    );
    assert_eq!(
        recorded(&asked.ones),
        [GetRestPermissionQuery {
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
        json!({ "restPermission": null })
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
    assert_eq!(recorded(&asked.ones), Vec::<GetRestPermissionQuery>::new());
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
            Vec::<GetRestPermissionsQuery>::new()
        );
        assert_eq!(recorded(&asked.ones), Vec::<GetRestPermissionQuery>::new());
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
    let response = RestPermissionResponse::from(view_of("rest:billing:GET /api/invoices"));
    let object = RestPermissionObject::from(response.clone());
    let page = RestPermissionPageObject::from(RestPermissionPageResponse {
        items: vec![response],
        next_cursor: None,
    });

    assert_eq!(object.method, "GET");
    assert_eq!(object.template, "/api/invoices");
    assert!(object.flags.sensitive);
    assert_eq!(page.items, [object]);
    assert_eq!(page.next_cursor, None);
    assert!(RestPermissionFilterInput::default().service.is_none());
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

    let parsed = RestPermissionFilterInput::parse(Some(filter(vec![
        ("service", Value::String("billing".to_owned())),
        ("method", Value::String("POST".to_owned())),
        ("active", Value::Boolean(true)),
        ("sensitive", Value::Boolean(false)),
        ("templatePrefix", Value::String("/api/".to_owned())),
    ])))
    .unwrap();

    assert_eq!(parsed.service.as_deref(), Some("billing"));
    assert_eq!(parsed.method.as_deref(), Some("POST"));
    assert_eq!(parsed.active, Some(true));
    assert_eq!(parsed.sensitive, Some(false));
    assert_eq!(parsed.template_prefix.as_deref(), Some("/api/"));
    assert!(RestPermissionFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["service", "method", "active", "sensitive", "templatePrefix"] {
        let wrong = filter(vec![(field, Value::List(Vec::new()))]);
        assert!(
            RestPermissionFilterInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
