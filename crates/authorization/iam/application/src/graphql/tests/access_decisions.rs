use std::sync::Arc;
use std::time::SystemTime;

use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use rstest::rstest;
use serde_json::json;
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::access_decision_fixtures::{decision_id, entry};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{AccessDecisionFilterInput, IamMutation, IamQuery};
use crate::http::IamState;
use crate::query::get_access_decision::GetAccessDecisionQuery;
use crate::query::get_access_decisions::{AccessDecisionPage, GetAccessDecisionsQuery};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const DECISION: &str = "query($id: ID!) { accessDecision(id: $id) { id decision reason status \
    subjectKind denied policyVersion routeTemplate } }";
const DECISIONS: &str = "query($first: Int, $after: String, $filter: AccessDecisionFilterInput) \
    { accessDecisions(first: $first, after: $after, filter: $filter) \
    { items { id decision } nextCursor } }";

fn schema(failure: Option<fn() -> IamError>) -> IamSchema {
    let queries = Arc::new(
        FakeQueryBus::answering(move |_query: GetAccessDecisionsQuery| {
            failure.map_or_else(
                || {
                    Ok(AccessDecisionPage {
                        entries: vec![entry(2, 2_000_000_000), entry(1, 1_000_000_000)],
                        next: Some("sealed-token".to_owned()),
                    })
                },
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: GetAccessDecisionQuery| {
            failure.map_or_else(
                || Ok((query.id == decision_id(1)).then(|| entry(1, 1_000_000_000))),
                |refuse| Err(refuse()),
            )
        }),
    );
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> = queries;
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    Schema::build(IamQuery, IamMutation, EmptySubscription)
        .data(state)
        .finish()
}

async fn run(
    schema: &IamSchema,
    authenticated: bool,
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    if authenticated {
        request = request.data(Some(principal()));
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

fn range() -> serde_json::Value {
    json!({ "from": "2026-11-23T08:00:00Z", "until": "2026-11-23T09:00:00Z", "decision": "deny" })
}

#[tokio::test]
async fn the_decisions_are_listed_newest_first_with_the_cursor_of_the_next_page() {
    let response = run(
        &schema(None),
        true,
        DECISIONS,
        json!({ "first": 2, "filter": range() }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let page = &data["accessDecisions"];
    assert_eq!(page["items"][0]["id"], decision_id(2).to_string());
    assert_eq!(page["items"][1]["id"], decision_id(1).to_string());
    assert_eq!(page["items"][0]["decision"], "deny");
    assert_eq!(page["nextCursor"], "sealed-token");
}

#[tokio::test]
async fn a_decision_is_read_by_id() {
    let response = run(
        &schema(None),
        true,
        DECISION,
        json!({ "id": decision_id(1).to_string() }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let found = &data["accessDecision"];
    assert_eq!(found["id"], decision_id(1).to_string());
    assert_eq!(found["reason"], "permission_missing");
    assert_eq!(found["status"], 403);
    assert_eq!(found["subjectKind"], "user");
    assert_eq!(found["denied"], json!(["user:read"]));
    assert_eq!(found["policyVersion"], 7);
    assert_eq!(found["routeTemplate"], "/api/users/{id}");
}

#[tokio::test]
async fn an_absent_decision_is_null() {
    let response = run(
        &schema(None),
        true,
        DECISION,
        json!({ "id": decision_id(9).to_string() }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["accessDecision"], json!(null));
}

#[rstest]
#[case::no_filter(json!({}))]
#[case::no_range(json!({ "filter": { "decision": "deny" } }))]
#[case::no_until(json!({ "filter": { "from": "2026-11-23T08:00:00Z" } }))]
#[tokio::test]
async fn a_missing_range_is_a_validation_failure(#[case] variables: serde_json::Value) {
    let response = run(&schema(None), true, DECISIONS, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_page_size_above_the_maximum_is_a_validation_failure() {
    let response = run(
        &schema(None),
        true,
        DECISIONS,
        json!({ "first": 501, "filter": range() }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_is_a_validation_failure() {
    let response = run(&schema(None), true, DECISION, json!({ "id": "nope" })).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[rstest]
#[case::timeout(|| IamError::AccessLogTimeout, "QUERY_TIMEOUT")]
#[case::unavailable(|| IamError::AccessLogUnavailable, "SERVICE_UNAVAILABLE")]
#[tokio::test]
async fn a_failing_log_store_has_its_own_code(
    #[case] failure: fn() -> IamError,
    #[case] code: &str,
) {
    let response = run(
        &schema(Some(failure)),
        true,
        DECISIONS,
        json!({ "filter": range() }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(code)));
}

#[tokio::test]
async fn a_request_without_a_caller_is_unauthenticated() {
    let response = run(
        &schema(None),
        false,
        DECISIONS,
        json!({ "filter": range() }),
    )
    .await;

    assert_ne!(response.errors.len(), 0);
}

#[test]
fn the_filter_input_prints_its_type_and_its_fields() {
    let filter = AccessDecisionFilterInput {
        subject_id: Some("alice".to_owned()),
        ..AccessDecisionFilterInput::default()
    };

    let printed = format!("{filter:?}");

    assert!(printed.starts_with("AccessDecisionFilterInput"));
    assert!(printed.contains("alice"));
}

#[test]
fn the_filter_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let filter = Value::Object(
        [("from", "2026-11-23T08:00:00Z"), ("subjectId", "alice")]
            .into_iter()
            .map(|(name, value)| (Name::new(name), Value::String(value.to_owned())))
            .collect(),
    );

    let parsed = AccessDecisionFilterInput::parse(Some(filter)).unwrap();

    assert_eq!(parsed.from.as_deref(), Some("2026-11-23T08:00:00Z"));
    assert_eq!(parsed.subject_id.as_deref(), Some("alice"));
    assert_eq!(parsed.until, None);
    assert!(AccessDecisionFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for field in [
        "from",
        "until",
        "subjectId",
        "subjectKind",
        "decision",
        "reason",
        "upstream",
        "routeId",
        "status",
    ] {
        let wrong =
            Value::Object(std::iter::once((Name::new(field), Value::Boolean(true))).collect());
        assert!(
            AccessDecisionFilterInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
