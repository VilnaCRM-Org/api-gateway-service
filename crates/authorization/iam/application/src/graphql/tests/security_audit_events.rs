use std::sync::PoisonError;

use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::AuditOutcome;
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::security_audit_fixtures::{
    COMMITTED, REJECTED, UNKNOWN, actor, asked_count, scenario, stored,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const EVENT: &str = "query($id: ID!) { securityAuditEvent(id: $id) { id seq occurredAt actor \
    action targetType targetId before after outcome reason policyVersion prevHash hash } }";
const EVENTS: &str = "query($first: Int, $after: String, $filter: SecurityAuditEventFilterInput) \
    { securityAuditEvents(first: $first, after: $after, filter: $filter) \
    { items { id seq outcome } nextCursor } }";

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

#[tokio::test]
async fn a_committed_record_is_read_with_its_summaries_and_its_hashes() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        EVENT,
        json!({ "id": COMMITTED }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let record = &data["securityAuditEvent"];
    assert_eq!(record["id"], COMMITTED);
    assert_eq!(record["seq"], 1);
    assert_eq!(record["actor"], actor().to_string());
    assert_eq!(record["action"], "role.update");
    assert_eq!(record["targetType"], "role");
    assert_eq!(record["targetId"], "r-1");
    assert_eq!(record["before"], "name=readers");
    assert_eq!(record["after"], "name=writers");
    assert_eq!(record["outcome"], "committed");
    assert_eq!(record["reason"], json!(null));
    assert_eq!(record["policyVersion"], 7);
    assert_eq!(record["prevHash"], "0".repeat(64));
    assert_eq!(record["hash"], format!("{}01", "0".repeat(62)));
    assert!(record["occurredAt"].as_str().unwrap().ends_with('Z'));
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.gets[0].actor, actor());
}

#[tokio::test]
async fn an_unknown_record_is_null() {
    let (state, _asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        EVENT,
        json!({ "id": UNKNOWN }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "securityAuditEvent": null })
    );
}

#[tokio::test]
async fn a_malformed_id_and_a_missing_caller_are_refused_without_a_query() {
    let (state, asked) = scenario(stored(), None);
    let schema = schema(Some(state));

    let invalid = run(&schema, Caller::Valid, EVENT, json!({ "id": "nope" })).await;
    let refused = run(&schema, Caller::Refused, EVENT, json!({ "id": COMMITTED })).await;
    let absent = run(&schema, Caller::Absent, EVENT, json!({ "id": COMMITTED })).await;

    assert_eq!(error_code(&invalid), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&invalid), ["\"id\""]);
    assert_eq!(error_code(&refused), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(error_code(&absent), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_page_lists_the_newest_records_first_with_the_cursor_of_the_older_page() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        EVENTS,
        json!({ "first": 1 }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "securityAuditEvents": {
            "items": [{ "id": REJECTED, "seq": 2, "outcome": "rejected" }],
            "nextCursor": "2",
        } })
    );
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 1);
    assert_eq!(recorded.lists[0].actor, actor());
}

#[tokio::test]
async fn a_list_without_arguments_asks_for_the_first_page_of_30_without_a_condition() {
    let (state, asked) = scenario(stored(), None);

    let response = run(&schema(Some(state)), Caller::Valid, EVENTS, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 30);
    assert_eq!(recorded.lists[0].before_seq, None);
    assert_eq!(
        recorded.lists[0].filter,
        iam_domain::SecurityAuditFilter::new()
    );
}

#[tokio::test]
async fn the_filter_and_the_cursor_reach_the_query() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        EVENTS,
        json!({
            "after": "2",
            "filter": {
                "from": "2026-11-23T08:00:00Z",
                "until": "2026-11-24T08:00:00Z",
                "actor": actor().to_string(),
                "action": "role.create",
                "targetType": "role",
                "targetId": "r-1",
                "outcome": "rejected",
            },
        }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let query = asked.lock().unwrap_or_else(PoisonError::into_inner).lists[0].clone();
    assert_eq!(query.before_seq, Some(2));
    assert_eq!(query.filter.outcome(), Some(AuditOutcome::Rejected));
    assert_eq!(query.filter.target_id(), Some("r-1"));
    assert_eq!(query.filter.since_micros(), Some(1_795_420_800_000_000));
}

#[rstest]
#[case::zero(json!({ "first": 0 }), "\"limit\"")]
#[case::cursor(json!({ "after": "nope" }), "\"after\"")]
#[case::outcome(json!({ "filter": { "outcome": "maybe" } }), "\"outcome\"")]
#[case::time(json!({ "filter": { "from": "yesterday" } }), "\"from\"")]
#[tokio::test]
async fn an_invalid_argument_is_a_validation_failure_without_a_query(
    #[case] variables: serde_json::Value,
    #[case] property: &str,
) {
    let (state, asked) = scenario(stored(), None);

    let response = run(&schema(Some(state)), Caller::Valid, EVENTS, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_list_without_a_valid_caller_is_unauthenticated() {
    let (state, asked) = scenario(stored(), None);
    let schema = schema(Some(state));

    let refused = run(&schema, Caller::Refused, EVENTS, json!({})).await;
    let absent = run(&schema, Caller::Absent, EVENTS, json!({})).await;

    assert_eq!(error_code(&refused), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(error_code(&absent), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(asked_count(&asked), 0);
}

#[rstest]
#[case::forbidden(|| IamError::Forbidden, "FORBIDDEN")]
#[case::storage(|| IamError::Storage("down".into()), "INTERNAL_SERVER_ERROR")]
#[tokio::test]
async fn a_refused_read_is_the_error_of_the_field(
    #[case] refusal: fn() -> IamError,
    #[case] code: &str,
) {
    let (state, _asked) = scenario(stored(), Some(refusal));
    let schema = schema(Some(state));

    let one = run(&schema, Caller::Valid, EVENT, json!({ "id": COMMITTED })).await;
    let many = run(&schema, Caller::Valid, EVENTS, json!({})).await;

    assert_eq!(error_code(&one), Some(code_of(code)));
    assert_eq!(error_code(&many), Some(code_of(code)));
}

#[tokio::test]
async fn a_request_without_the_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, EVENTS, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn a_list_without_the_filter_argument_searches_without_a_condition() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        "{ securityAuditEvents { items { id } nextCursor } }",
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let query = asked.lock().unwrap_or_else(PoisonError::into_inner).lists[0].clone();
    assert_eq!(query.limit, 30);
    assert_eq!(query.filter, iam_domain::SecurityAuditFilter::new());
}

#[test]
fn the_filter_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    use crate::graphql::security_audit_event::SecurityAuditEventFilterInput;

    let filter = Value::Object(
        [
            ("outcome", "rejected"),
            ("targetType", "role"),
            ("targetId", "r-1"),
        ]
        .into_iter()
        .map(|(name, value)| (Name::new(name), Value::String(value.to_owned())))
        .collect(),
    );

    let parsed = SecurityAuditEventFilterInput::parse(Some(filter)).unwrap();

    assert_eq!(parsed.outcome.as_deref(), Some("rejected"));
    assert_eq!(parsed.target_type.as_deref(), Some("role"));
    assert_eq!(parsed.target_id.as_deref(), Some("r-1"));
    assert_eq!(parsed.from, None);
    assert!(SecurityAuditEventFilterInput::parse(Some(Value::Boolean(true))).is_err());
    let wrong_outcome =
        Value::Object(std::iter::once((Name::new("outcome"), Value::Boolean(true))).collect());
    assert!(SecurityAuditEventFilterInput::parse(Some(wrong_outcome)).is_err());
}
