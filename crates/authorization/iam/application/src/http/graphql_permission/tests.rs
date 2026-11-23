use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use iam_domain::{GqlName, PermissionId, ServiceName};
use rstest::rstest;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql_permission_fixtures::{
    Answers, Asked, PERMISSION, ROLE, VERSION, recorded, scenario, view_of,
};
use crate::http::{IamState, router};
use crate::query::get_graphql_permission::GetGraphQlPermissionQuery;
use crate::query::get_graphql_permissions::{GetGraphQlPermissionsQuery, GraphQlPermissionPage};

fn app(answers: Answers) -> (Router, Asked) {
    let (state, asked) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn get(uri: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

async fn answer(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn permission_id() -> PermissionId {
    PermissionId::parse(PERMISSION).unwrap()
}

#[tokio::test]
async fn the_list_is_a_page_of_entries_with_the_cursor_of_the_next_page() {
    let (app, asked) = app(Answers::default());

    let (status, body) = answer(app, get("/graphql-permissions")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["nextCursor"], json!(PERMISSION));
    let item = &body["items"][0];
    assert_eq!(item["id"], json!(PERMISSION));
    assert_eq!(item["key"], json!("gql:billing:Mutation.pay"));
    assert_eq!(item["service"], json!("billing"));
    assert_eq!(item["type"], json!("Mutation"));
    assert_eq!(item["field"], json!("pay"));
    assert_eq!(
        item["flags"],
        json!({"sensitive": true, "auditAlways": false})
    );
    assert_eq!(item["active"], json!(true));
    assert_eq!(item["versions"], json!([VERSION]));
    assert_eq!(item["roles"], json!([ROLE]));
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
async fn the_introspection_entry_shows_the_introspection_name_as_type_and_field() {
    let answers = Answers {
        page: Ok(GraphQlPermissionPage {
            permissions: vec![view_of("gql:billing:__introspection")],
            next_after: None,
        }),
        ..Answers::default()
    };
    let (app, _asked) = app(answers);

    let (status, body) = answer(app, get("/graphql-permissions")).await;

    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];
    assert_eq!(item["type"], json!("__introspection"));
    assert_eq!(item["field"], json!("__introspection"));
    assert!(body.get("nextCursor").is_none());
}

#[tokio::test]
async fn the_list_passes_its_filters_to_the_query() {
    let (app, asked) = app(Answers::default());
    let uri = format!(
        "/graphql-permissions?limit=5&after={PERMISSION}&service=billing&type=Mutation\
         &active=true&sensitive=false&keyPrefix=gql:billing:Mutation."
    );

    let (status, _body) = answer(app, get(&uri)).await;

    assert_eq!(status, StatusCode::OK);
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

#[rstest]
#[case::limit_zero("/graphql-permissions?limit=0", "limit")]
#[case::limit_over("/graphql-permissions?limit=101", "limit")]
#[case::cursor("/graphql-permissions?after=nope", "after")]
#[case::service("/graphql-permissions?service=Not%20A%20Service", "service")]
#[case::type_name("/graphql-permissions?type=1Bad", "type")]
#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_naming_it_and_asks_nothing(
    #[case] uri: &str,
    #[case] property: &str,
) {
    let (app, asked) = app(Answers::default());

    let (status, body) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!(property));
    assert_eq!(
        recorded(&asked.pages),
        Vec::<GetGraphQlPermissionsQuery>::new()
    );
}

#[tokio::test]
async fn an_unknown_list_parameter_is_a_client_error() {
    let (app, asked) = app(Answers::default());

    let (status, _body) = answer(app, get("/graphql-permissions?colour=red")).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(
        recorded(&asked.pages),
        Vec::<GetGraphQlPermissionsQuery>::new()
    );
}

#[tokio::test]
async fn one_entry_is_read_by_its_identifier() {
    let (app, asked) = app(Answers::default());

    let (status, body) = answer(app, get(&format!("/graphql-permissions/{PERMISSION}"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], json!(PERMISSION));
    assert_eq!(body["key"], json!("gql:billing:Mutation.pay"));
    assert_eq!(body["versions"], json!([VERSION]));
    assert_eq!(
        recorded(&asked.ones),
        [GetGraphQlPermissionQuery {
            id: permission_id()
        }]
    );
}

#[tokio::test]
async fn an_unknown_entry_is_a_404_problem() {
    let answers = Answers {
        one: Ok(None),
        ..Answers::default()
    };
    let (app, _asked) = app(answers);

    let (status, body) = answer(app, get(&format!("/graphql-permissions/{PERMISSION}"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], json!(404));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_and_asks_nothing() {
    let (app, asked) = app(Answers::default());

    let (status, body) = answer(app, get("/graphql-permissions/not-a-uuid")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(
        recorded(&asked.ones),
        Vec::<GetGraphQlPermissionQuery>::new()
    );
}

#[rstest]
#[case::list("/graphql-permissions")]
#[case::one("/graphql-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad")]
#[tokio::test]
async fn a_request_without_a_token_is_the_401_problem(#[case] uri: &str) {
    let (app, asked) = app(Answers::default());
    let mut request = get(uri);
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, body) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(
        recorded(&asked.pages),
        Vec::<GetGraphQlPermissionsQuery>::new()
    );
    assert_eq!(
        recorded(&asked.ones),
        Vec::<GetGraphQlPermissionQuery>::new()
    );
}

#[rstest]
#[case::list(Answers { page: Err(|| IamError::Storage("down".into())), ..Answers::default() }, "/graphql-permissions")]
#[case::one(Answers { one: Err(|| IamError::Storage("down".into())), ..Answers::default() }, "/graphql-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad")]
#[tokio::test]
async fn a_storage_failure_is_an_internal_problem(#[case] answers: Answers, #[case] uri: &str) {
    let (app, _asked) = app(answers);

    let (status, _body) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
