//! Tests of the GraphQL reads of the bulk operations.

use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use rstest::rstest;
use serde_json::json;

use super::BulkPropagationObject;
use crate::bulk_operation_fixtures::{
    COMPLETED, REQUESTER, RUNNING, UNKNOWN, asked_count, scenario, stored,
};
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::bulk_operation::dto::BulkPropagationResponse;
use crate::principal::Principal;

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const READ_ONE: &str = "query($id: ID!) { bulkOperation(id: $id) { id kind status totalRecords \
    appliedRecords firstVersion lastVersion requester error \
    propagation { status policyVersion podsAcknowledged podsTimedOut } } }";

const READ_PAGE: &str = "query($first: Int, $after: String) { \
    bulkOperations(first: $first, after: $after) { items { id status } nextCursor } }";

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Data(Option<Principal>),
}

async fn run(
    query: &str,
    caller: Caller,
    variables: serde_json::Value,
) -> (
    async_graphql::Response,
    crate::bulk_operation_fixtures::Asked,
) {
    let (state, asked) = scenario(stored(), None);
    let schema: IamSchema = Schema::build(IamQuery, IamMutation, EmptySubscription)
        .data(state)
        .finish();
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    (schema.execute(request).await, asked)
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
async fn a_bulk_operation_is_read_with_its_progress_and_a_null_propagation() {
    let (response, _asked) = run(
        READ_ONE,
        Caller::Data(Some(principal())),
        json!({ "id": RUNNING }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let operation = &data["bulkOperation"];
    assert_eq!(operation["id"], RUNNING);
    assert_eq!(operation["kind"], "role_deletion");
    assert_eq!(operation["status"], "running");
    assert_eq!(operation["appliedRecords"], 1_000);
    assert_eq!(operation["totalRecords"], 2_500);
    assert_eq!(operation["firstVersion"], 4);
    assert_eq!(operation["lastVersion"], 5);
    assert_eq!(operation["requester"], REQUESTER);
    assert_eq!(operation["propagation"], json!(null));
}

#[tokio::test]
async fn an_unknown_bulk_operation_is_null() {
    let (response, _asked) = run(
        READ_ONE,
        Caller::Data(Some(principal())),
        json!({ "id": UNKNOWN }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "bulkOperation": null })
    );
}

#[tokio::test]
async fn the_operations_are_listed_in_pages() {
    let (response, _asked) = run(
        READ_PAGE,
        Caller::Data(Some(principal())),
        json!({ "first": 1 }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let page = &data["bulkOperations"];
    assert_eq!(page["items"][0]["id"], RUNNING);
    assert_eq!(page["nextCursor"], RUNNING);

    let (second, _asked) = run(
        READ_PAGE,
        Caller::Data(Some(principal())),
        json!({ "first": 1, "after": RUNNING }),
    )
    .await;
    let data = second.data.into_json().unwrap();
    assert_eq!(data["bulkOperations"]["items"][0]["id"], COMPLETED);
    assert_eq!(data["bulkOperations"]["nextCursor"], json!(null));
}

#[rstest]
#[case::id(READ_ONE, json!({ "id": "nope" }))]
#[case::limit(READ_PAGE, json!({ "first": 0 }))]
#[case::cursor(READ_PAGE, json!({ "after": "nope" }))]
#[tokio::test]
async fn an_invalid_value_is_a_validation_failure(
    #[case] query: &str,
    #[case] variables: serde_json::Value,
) {
    let (response, asked) = run(query, Caller::Data(Some(principal())), variables).await;

    assert_eq!(
        error_code(&response),
        Some(Value::String("VALIDATION_FAILED".to_owned()))
    );
    assert_eq!(asked_count(&asked), 0);
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::unauthenticated(Caller::Data(None))]
#[tokio::test]
async fn the_fields_need_an_authenticated_caller(#[case] caller: Caller) {
    let (response, asked) = run(READ_ONE, caller, json!({ "id": RUNNING })).await;

    assert_eq!(
        error_code(&response),
        Some(Value::String("UNAUTHENTICATED".to_owned()))
    );
    assert_eq!(asked_count(&asked), 0);
}

#[test]
fn a_propagation_keeps_its_status_version_and_pod_counts() {
    let response = BulkPropagationResponse {
        status: "acknowledged".to_owned(),
        policy_version: 7,
        pods_acknowledged: 3,
        pods_timed_out: 1,
    };

    assert_eq!(
        BulkPropagationObject::from(response),
        BulkPropagationObject {
            status: "acknowledged".to_owned(),
            policy_version: 7,
            pods_acknowledged: 3,
            pods_timed_out: 1,
        }
    );
}
