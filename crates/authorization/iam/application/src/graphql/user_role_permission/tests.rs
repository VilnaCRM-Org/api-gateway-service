use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::get_user_role_permissions::GetUserRolePermissionsQuery;
use crate::user_role_permission_fixtures::{PROJECT, recorded, scenario, view};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const READ: &str = "query($userId: ID!, $projectId: String, $service: String) { \
    userRolePermissions(userId: $userId, projectId: $projectId, service: $service) { \
    userId policyVersion permissions { key kind service wildcard scopes expiresAt \
    roles { id name } } } }";

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
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(READ).variables(Variables::from_json(variables));
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
async fn the_effective_permissions_have_the_data_of_the_rest_answer() {
    let (state, _queries, asked) = scenario(Ok(view()));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let permissions = &data["userRolePermissions"];
    assert_eq!(permissions["userId"], USER);
    assert_eq!(permissions["policyVersion"], 7);
    assert_eq!(
        permissions["permissions"][0]["key"],
        "rest:billing:GET /invoices"
    );
    assert_eq!(permissions["permissions"][0]["scopes"], json!(["all"]));
    assert_eq!(
        permissions["permissions"][0]["expiresAt"],
        "2027-01-15T08:00:00.000000Z"
    );
    assert_eq!(
        permissions["permissions"][0]["roles"][1]["name"],
        json!(null)
    );
    assert_eq!(permissions["permissions"][1]["wildcard"], true);
    assert_eq!(recorded(&asked).len(), 1);
}

#[tokio::test]
async fn the_project_and_the_service_reach_the_query() {
    let (state, _queries, asked) = scenario(Ok(view()));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER, "projectId": PROJECT, "service": "billing" }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let query = recorded(&asked).pop().unwrap();
    assert_eq!(query.project.unwrap().to_string(), PROJECT);
    assert_eq!(query.service.unwrap().as_str(), "billing");
}

#[rstest]
#[case::user(json!({ "userId": "nope" }))]
#[case::project(json!({ "userId": USER, "projectId": "nope" }))]
#[case::service(json!({ "userId": USER, "service": "Not A Service" }))]
#[tokio::test]
async fn an_invalid_value_is_a_validation_failure(#[case] variables: serde_json::Value) {
    let (state, _queries, asked) = scenario(Ok(view()));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        variables,
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(recorded(&asked), Vec::<GetUserRolePermissionsQuery>::new());
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::unauthenticated(Caller::Data(None))]
#[tokio::test]
async fn the_field_needs_an_authenticated_caller(#[case] caller: Caller) {
    let (state, _queries, asked) = scenario(Ok(view()));

    let response = run(&schema(Some(state)), caller, json!({ "userId": USER })).await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(recorded(&asked), Vec::<GetUserRolePermissionsQuery>::new());
}

#[tokio::test]
async fn a_schema_without_the_state_answers_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        json!({ "userId": USER }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn a_failing_read_is_an_internal_error() {
    let (state, _queries, _asked) = scenario(Err(|| IamError::Storage("down".into())));

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        json!({ "userId": USER }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}
