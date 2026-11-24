use std::sync::PoisonError;

use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::RevocationSource;
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::revocation_read_fixtures::{
    OPERATOR_REVOCATION, OTHER_USER, Stored, UNKNOWN, USER_SERVICE_REVOCATION, asked_count,
    operator, scenario, stored,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const ONE: &str = "query($id: ID!) { sessionRevocation(id: $id) \
    { id sessionId userId source actor revokedAt } }";
const MANY: &str = "query($first: Int, $after: String, $filter: SessionRevocationFilterInput) \
    { sessionRevocations(first: $first, after: $after, filter: $filter) \
    { items { id source } nextCursor } }";
const USER_CUTOFF: &str = "query($userId: ID!) { userTokenCutoff(userId: $userId) \
    { userId tokensValidAfter source actor updatedAt } }";
const GLOBAL_CUTOFF: &str = "{ globalTokenCutoff { tokensValidAfter source actor setAt } }";

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

#[tokio::test]
async fn a_revocation_is_read_with_its_source_actor_session_user_and_time() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ONE,
        json!({ "id": OPERATOR_REVOCATION }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let record = &data["sessionRevocation"];
    assert_eq!(record["id"], OPERATOR_REVOCATION);
    assert_eq!(record["sessionId"], "session-1");
    assert_eq!(record["userId"], USER);
    assert_eq!(record["source"], "operator");
    assert_eq!(record["actor"], operator().to_string());
    assert!(record["revokedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .gets
            .len(),
        1
    );
}

#[tokio::test]
async fn an_unknown_revocation_is_null() {
    let (state, _asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ONE,
        json!({ "id": UNKNOWN }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "sessionRevocation": null })
    );
}

#[tokio::test]
async fn a_malformed_id_and_a_missing_caller_are_refused_without_a_query() {
    let (state, asked) = scenario(stored(), None);
    let schema = schema(Some(state));

    let invalid = run(&schema, Caller::Valid, ONE, json!({ "id": "nope" })).await;
    let refused = run(
        &schema,
        Caller::Refused,
        ONE,
        json!({ "id": OPERATOR_REVOCATION }),
    )
    .await;
    let absent = run(
        &schema,
        Caller::Absent,
        ONE,
        json!({ "id": OPERATOR_REVOCATION }),
    )
    .await;

    assert_eq!(error_code(&invalid), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(error_code(&refused), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(error_code(&absent), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_page_lists_the_newest_revocations_first_with_the_cursor_of_the_older_page() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        MANY,
        json!({ "first": 1 }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "sessionRevocations": {
            "items": [{ "id": USER_SERVICE_REVOCATION, "source": "user-service" }],
            "nextCursor": USER_SERVICE_REVOCATION,
        } })
    );
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 1);
}

#[tokio::test]
async fn a_list_without_arguments_asks_for_the_first_page_of_30_without_a_condition() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        "{ sessionRevocations { items { id } nextCursor } }",
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let query = asked.lock().unwrap_or_else(PoisonError::into_inner).lists[0].clone();
    assert_eq!(query.limit, 30);
    assert_eq!(query.after, None);
    assert_eq!(query.user, None);
    assert_eq!(query.source, None);
}

#[tokio::test]
async fn the_filter_and_the_cursor_reach_the_query() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        MANY,
        json!({
            "after": OPERATOR_REVOCATION,
            "filter": {
                "userId": USER,
                "source": "operator",
                "from": "2026-11-23T08:00:00Z",
                "until": "2026-11-24T08:00:00Z",
            },
        }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let query = asked.lock().unwrap_or_else(PoisonError::into_inner).lists[0].clone();
    assert_eq!(
        query.after.map(|id| id.to_string()),
        Some(OPERATOR_REVOCATION.to_owned())
    );
    assert_eq!(
        query.user.map(|user| user.to_string()),
        Some(USER.to_owned())
    );
    assert_eq!(query.source, Some(RevocationSource::Operator));
    assert!(query.from.is_some() && query.until.is_some());
}

#[rstest]
#[case::zero(json!({ "first": 0 }))]
#[case::cursor(json!({ "after": "nope" }))]
#[case::user(json!({ "filter": { "userId": "nope" } }))]
#[case::source(json!({ "filter": { "source": "maybe" } }))]
#[case::time(json!({ "filter": { "from": "yesterday" } }))]
#[tokio::test]
async fn an_invalid_argument_is_a_validation_failure_without_a_query(
    #[case] variables: serde_json::Value,
) {
    let (state, asked) = scenario(stored(), None);

    let response = run(&schema(Some(state)), Caller::Valid, MANY, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_cutoff_of_a_user_is_read_with_its_instant_source_and_actor() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        USER_CUTOFF,
        json!({ "userId": USER }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let cutoff = &data["userTokenCutoff"];
    assert_eq!(cutoff["userId"], USER);
    assert_eq!(cutoff["source"], "operator");
    assert_eq!(cutoff["actor"], operator().to_string());
    assert!(cutoff["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert!(cutoff["updatedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .users
            .len(),
        1
    );
}

#[tokio::test]
async fn a_user_without_a_cutoff_is_null_and_a_malformed_user_is_refused() {
    let (state, asked) = scenario(stored(), None);
    let schema = schema(Some(state));

    let none = run(
        &schema,
        Caller::Valid,
        USER_CUTOFF,
        json!({ "userId": OTHER_USER }),
    )
    .await;
    let queries = asked_count(&asked);
    let invalid = run(
        &schema,
        Caller::Valid,
        USER_CUTOFF,
        json!({ "userId": "nope" }),
    )
    .await;

    assert!(none.errors.is_empty(), "{:?}", none.errors);
    assert_eq!(
        none.data.into_json().unwrap(),
        json!({ "userTokenCutoff": null })
    );
    assert_eq!(error_code(&invalid), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(asked_count(&asked), queries);
}

#[tokio::test]
async fn the_global_cutoff_is_read_with_its_instant_source_and_actor() {
    let (state, asked) = scenario(stored(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        GLOBAL_CUTOFF,
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let cutoff = &data["globalTokenCutoff"];
    assert_eq!(cutoff["source"], "operator");
    assert_eq!(cutoff["actor"], operator().to_string());
    assert!(cutoff["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert!(cutoff["setAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        asked.lock().unwrap_or_else(PoisonError::into_inner).globals,
        1
    );
}

#[tokio::test]
async fn a_global_cutoff_that_was_never_set_is_null() {
    let (state, _asked) = scenario(Stored::default(), None);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        GLOBAL_CUTOFF,
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "globalTokenCutoff": null })
    );
}

#[tokio::test]
async fn every_read_without_a_valid_caller_is_unauthenticated_without_a_query() {
    let (state, asked) = scenario(stored(), None);
    let schema = schema(Some(state));

    for (query, variables) in [
        (MANY, json!({})),
        (USER_CUTOFF, json!({ "userId": USER })),
        (GLOBAL_CUTOFF, json!({})),
    ] {
        let refused = run(&schema, Caller::Refused, query, variables.clone()).await;
        let absent = run(&schema, Caller::Absent, query, variables).await;

        assert_eq!(error_code(&refused), Some(code_of("UNAUTHENTICATED")));
        assert_eq!(error_code(&absent), Some(code_of("UNAUTHENTICATED")));
    }
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

    for (query, variables) in [
        (ONE, json!({ "id": OPERATOR_REVOCATION })),
        (MANY, json!({})),
        (USER_CUTOFF, json!({ "userId": USER })),
        (GLOBAL_CUTOFF, json!({})),
    ] {
        let response = run(&schema, Caller::Valid, query, variables).await;

        assert_eq!(error_code(&response), Some(code_of(code)));
    }
}

#[tokio::test]
async fn a_request_without_the_state_is_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, MANY, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_filter_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    use crate::graphql::revocation_read::SessionRevocationFilterInput;

    let filter = Value::Object(
        [("source", "operator"), ("until", "2026-11-23T08:00:00Z")]
            .into_iter()
            .map(|(name, value)| (Name::new(name), Value::String(value.to_owned())))
            .collect(),
    );

    let parsed = SessionRevocationFilterInput::parse(Some(filter)).unwrap();

    assert_eq!(parsed.source.as_deref(), Some("operator"));
    assert_eq!(parsed.until.as_deref(), Some("2026-11-23T08:00:00Z"));
    assert_eq!(parsed.from, None);
    assert!(parsed.user_id.is_none());
    assert!(SessionRevocationFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["userId", "source", "from", "until"] {
        let wrong_type =
            Value::Object(std::iter::once((Name::new(field), Value::Boolean(true))).collect());
        assert!(
            SessionRevocationFilterInput::parse(Some(wrong_type)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn the_filter_input_describes_itself_for_the_logs() {
    use crate::graphql::revocation_read::SessionRevocationFilterInput;

    let described = format!("{:?}", SessionRevocationFilterInput::default());

    assert!(
        described.starts_with("SessionRevocationFilterInput"),
        "{described}"
    );
}
