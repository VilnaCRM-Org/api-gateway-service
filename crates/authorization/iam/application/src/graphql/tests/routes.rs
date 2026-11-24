use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{
    EnforcementMode, EntityVersion, HttpMethod, PropagationOutcome, RetryPolicy, RouteFlag,
};
use rstest::rstest;
use serde_json::json;

use crate::command::update_route::CorsChange;
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::list_routes::RoutePage;
use crate::route_fixtures::{
    Answers, ROUTE, UPSTREAM, actor, receipt, receipt_at, recorded, route, route_id, scenario,
    upstream_id,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const FIELDS: &str = "id host methods pathPattern service upstreamId graphql streaming anonymous \
    enforcement bodyLimitBytes requestTimeoutMs idleTimeoutMs retryPolicy ratePolicyIds \
    cors { origins methods headers allowCredentials maxAgeSeconds } system version createdAt \
    updatedAt";

fn create_mutation() -> String {
    format!(
        "mutation($input: CreateRouteInput!) {{ createRoute(input: $input) \
         {{ {FIELDS} propagation {{ status policyVersion }} }} }}"
    )
}

fn update_mutation() -> String {
    format!("mutation($input: UpdateRouteInput!) {{ updateRoute(input: $input) {{ {FIELDS} }} }}")
}

const DELETE: &str = "mutation($input: DeleteRouteInput!) { deleteRoute(input: $input) \
    { id version policyVersion propagation { status } } }";
const ROUTE_BY_ID: &str = "query($id: ID!) { route(id: $id) { id host version } }";
const ROUTES: &str = "query($first: Int, $after: String, $filter: RouteFilterInput) \
    { routes(first: $first, after: $after, filter: $filter) { items { id host version } nextCursor } }";

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

fn created() -> serde_json::Value {
    json!({ "input": {
        "host": "app.example.test",
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
    } })
}

fn route_json(version: i64) -> serde_json::Value {
    json!({
        "id": ROUTE,
        "host": "app.example.test",
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": false,
        "streaming": false,
        "anonymous": false,
        "enforcement": "enforce",
        "bodyLimitBytes": 1_048_576,
        "requestTimeoutMs": 30_000,
        "idleTimeoutMs": 60_000,
        "retryPolicy": "none",
        "ratePolicyIds": [],
        "cors": null,
        "system": false,
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:05:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_route_returns_the_same_data_as_over_rest() {
    let (state, commands, _queries, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        created(),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let mut expected = route_json(1);
    expected["propagation"] = json!(null);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "createRoute": expected })
    );
    assert_eq!(commands.dispatched(), ["CreateRouteCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].draft.host, "app.example.test");
    assert_eq!(sent[0].draft.methods, [HttpMethod::Get]);
    assert_eq!(sent[0].draft.upstream_id, upstream_id());
    assert_eq!(sent[0].draft.body_limit, 1_048_576);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn every_optional_member_of_the_input_reaches_the_command() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "host": "app.example.test",
        "methods": ["GET", "POST"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": true,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 2048,
        "requestTimeoutMs": 1000,
        "idleTimeoutMs": 2000,
        "retryPolicy": "idempotent",
        "ratePolicyIds": ["0190f2a8-7b3c-7d4e-8f10-1234567890ae"],
        "cors": {
            "origins": ["https://app.example.test"],
            "methods": ["GET"],
            "headers": ["x-a"],
            "allowCredentials": true,
            "maxAgeSeconds": 60,
        },
        "idempotencyKey": "create-route",
        "consistency": "PUBLISHED",
    } });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        variables,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let draft = &recorded(&asked.commands)[0].draft;
    assert_eq!(draft.methods, [HttpMethod::Get, HttpMethod::Post]);
    assert!(draft.flags.has(RouteFlag::Graphql));
    assert!(draft.flags.has(RouteFlag::Streaming));
    assert!(draft.flags.has(RouteFlag::Anonymous));
    assert_eq!(draft.enforcement, EnforcementMode::Audit);
    assert_eq!(draft.body_limit, 2048);
    assert_eq!(draft.retry, RetryPolicy::Idempotent);
    assert_eq!(draft.rate_policies.len(), 1);
    let cors = draft.cors.as_ref().unwrap();
    assert!(cors.allow_credentials);
    assert_eq!(cors.max_age_seconds, 60);
    assert!(recorded(&asked.commands)[0].idempotency.is_some());
}

#[tokio::test]
async fn a_pending_write_reports_its_propagation() {
    let (state, ..) = scenario(Answers {
        receipt: receipt(Some(5)).with_propagation(PropagationOutcome::CommittedPending),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        created(),
    )
    .await;

    assert_eq!(
        response.data.into_json().unwrap()["createRoute"]["propagation"],
        json!({ "status": "COMMITTED_PENDING", "policyVersion": 5 })
    );
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::refused(Caller::Refused)]
#[tokio::test]
async fn a_creation_without_an_authenticated_caller_is_unauthenticated(#[case] caller: Caller) {
    let (state, commands, ..) = scenario(Answers::default());

    let response = run(&schema(Some(state)), caller, &create_mutation(), created()).await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_schema_without_the_state_fails_with_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, &create_mutation(), created()).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[rstest]
#[case::empty_host(json!({ "host": "" }), "\"host\"")]
#[case::empty_path(json!({ "pathPattern": "" }), "\"pathPattern\"")]
#[case::empty_service(json!({ "service": "" }), "\"service\"")]
#[case::method(json!({ "methods": ["TRACE"] }), "\"methods\"")]
#[case::enforcement(json!({ "enforcement": "never" }), "\"enforcement\"")]
#[case::retry(json!({ "retryPolicy": "always" }), "\"retryPolicy\"")]
#[case::cors_method(json!({ "cors": { "origins": ["https://a.test"], "methods": ["TRACE"] } }), "\"methods\"")]
#[case::upstream(json!({ "upstreamId": "nope" }), "\"upstreamId\"")]
#[tokio::test]
async fn an_invalid_input_is_a_validation_failure_naming_the_property(
    #[case] member: serde_json::Value,
    #[case] property: &str,
) {
    let (state, commands, ..) = scenario(Answers::default());
    let mut variables = created();
    for (name, value) in member.as_object().unwrap() {
        variables["input"][name] = value.clone();
    }

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        variables,
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_invalid_idempotency_key_or_consistency_is_a_validation_failure() {
    let (state, commands, ..) = scenario(Answers::default());
    let schema = schema(Some(state));
    let mut bad_key = created();
    bad_key["input"]["idempotencyKey"] = json!("");
    let mut propagated = created();
    propagated["input"]["consistency"] = json!("PROPAGATED");

    let key = run(&schema, Caller::Valid, &create_mutation(), bad_key).await;
    let mode = run(&schema, Caller::Valid, &create_mutation(), propagated).await;

    assert_eq!(error_code(&key), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&key), ["\"idempotencyKey\""]);
    assert_eq!(error_code(&mode), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&mode), ["\"consistency\""]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::conflict(|| IamError::RouteTableConflict { code: "same_pattern" }, "CONFLICT")]
#[case::system_entry(|| IamError::SystemEntry, "CONFLICT")]
#[case::forbidden(|| IamError::Forbidden, "FORBIDDEN")]
#[case::invalid(
    || IamError::from(vec![iam_domain::InvalidRoute::HostFormat]),
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn a_refusal_of_the_command_is_its_graphql_code(
    #[case] refusal: fn() -> IamError,
    #[case] expected: &str,
) {
    let answers = Answers {
        command: Err(refusal),
        ..Answers::default()
    };
    let (state, ..) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        created(),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[tokio::test]
async fn a_route_is_read_by_id_and_an_unknown_one_is_null() {
    let (state, ..) = scenario(Answers::default());
    let (empty, ..) = scenario(Answers {
        route: Ok(None),
        ..Answers::default()
    });

    let found = run(
        &schema(Some(state)),
        Caller::Valid,
        ROUTE_BY_ID,
        json!({ "id": ROUTE }),
    )
    .await;
    let unknown = run(
        &schema(Some(empty)),
        Caller::Valid,
        ROUTE_BY_ID,
        json!({ "id": ROUTE }),
    )
    .await;

    assert_eq!(
        found.data.into_json().unwrap(),
        json!({ "route": { "id": ROUTE, "host": "app.example.test", "version": 1 } })
    );
    assert_eq!(unknown.data.into_json().unwrap(), json!({ "route": null }));
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_or_a_missing_caller_fails_the_read() {
    let (state, ..) = scenario(Answers::default());
    let schema = schema(Some(state));

    let bad_id = run(&schema, Caller::Valid, ROUTE_BY_ID, json!({ "id": "nope" })).await;
    let absent = run(&schema, Caller::Absent, ROUTE_BY_ID, json!({ "id": ROUTE })).await;

    assert_eq!(error_code(&bad_id), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(error_code(&absent), Some(code_of("UNAUTHENTICATED")));
}

#[tokio::test]
async fn a_page_of_routes_lists_its_items_its_cursor_and_passes_the_filters() {
    let (state, _commands, _queries, asked) = scenario(Answers {
        page: Ok(RoutePage {
            routes: vec![route(1)],
            next_after: Some(route_id()),
        }),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ROUTES,
        json!({ "first": 1, "after": ROUTE, "filter": {
            "host": "app.example.test", "upstream": UPSTREAM, "service": "core" } }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "routes": {
            "items": [{ "id": ROUTE, "host": "app.example.test", "version": 1 }],
            "nextCursor": ROUTE,
        } })
    );
    let lists = recorded(&asked.lists);
    assert_eq!(lists[0].limit, 1);
    assert_eq!(lists[0].after, Some(route_id()));
    assert_eq!(lists[0].host.as_ref().unwrap().as_str(), "app.example.test");
    assert_eq!(lists[0].upstream, Some(upstream_id()));
    assert_eq!(lists[0].service.as_ref().unwrap().as_str(), "core");
}

#[tokio::test]
async fn a_list_without_arguments_asks_for_the_first_page_of_30() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, ROUTES, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let lists = recorded(&asked.lists);
    assert_eq!(lists[0].limit, 30);
    assert_eq!(lists[0].host, None);
}

#[rstest]
#[case::zero(json!({ "first": 0 }))]
#[case::above_the_maximum(json!({ "first": 101 }))]
#[case::cursor(json!({ "after": "nope" }))]
#[case::host(json!({ "filter": { "host": "Bad Host" } }))]
#[tokio::test]
async fn an_invalid_page_argument_is_a_validation_failure(#[case] variables: serde_json::Value) {
    let (state, _commands, queries, _asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, ROUTES, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_updated_route_returns_the_new_version_and_dispatches_the_patch() {
    let (state, commands, _queries, asked) = scenario(Answers {
        receipt: receipt_at(2, Some(8)),
        route: Ok(Some(route(2))),
        ..Answers::default()
    });
    let variables = json!({ "input": {
        "id": ROUTE,
        "expectedVersion": 1,
        "requestTimeoutMs": 5000,
        "cors": null,
    } });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &update_mutation(),
        variables,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "updateRoute": route_json(2) })
    );
    assert_eq!(commands.dispatched(), ["UpdateRouteCommand"]);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].route_id, route_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].patch.request_timeout_ms, Some(5000));
    assert_eq!(sent[0].patch.cors, CorsChange::Remove);
    assert_eq!(sent[0].patch.host, None);
}

#[tokio::test]
async fn every_member_of_an_update_reaches_the_patch() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "id": ROUTE,
        "expectedVersion": 1,
        "host": "other.example.test",
        "methods": ["POST"],
        "pathPattern": "/api/other",
        "service": "payment",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": true,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 10,
        "requestTimeoutMs": 11,
        "idleTimeoutMs": 12,
        "retryPolicy": "idempotent",
        "ratePolicyIds": ["0190f2a8-7b3c-7d4e-8f10-1234567890ae"],
        "cors": { "origins": ["https://app.example.test"] },
        "idempotencyKey": "update-route",
        "consistency": "PUBLISHED",
    } });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &update_mutation(),
        variables,
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let patch = &recorded(&asked.updates)[0].patch;
    assert_eq!(patch.host.as_deref(), Some("other.example.test"));
    assert_eq!(patch.methods, Some(vec![HttpMethod::Post]));
    assert_eq!(patch.service.as_deref(), Some("payment"));
    assert_eq!(patch.enforcement, Some(EnforcementMode::Audit));
    assert_eq!(patch.retry, Some(RetryPolicy::Idempotent));
    assert_eq!(patch.rate_policies.as_ref().map(Vec::len), Some(1));
    assert!(matches!(patch.cors, CorsChange::Set(_)));
    assert!(recorded(&asked.updates)[0].idempotency.is_some());
}

#[rstest]
#[case::no_version(json!({ "id": ROUTE }), "PRECONDITION_REQUIRED")]
#[case::id(json!({ "id": "nope", "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[case::method(
    json!({ "id": ROUTE, "expectedVersion": 1, "methods": ["TRACE"] }),
    "VALIDATION_FAILED"
)]
#[case::host(
    json!({ "id": ROUTE, "expectedVersion": 1, "host": "" }),
    "VALIDATION_FAILED"
)]
#[case::key(
    json!({ "id": ROUTE, "expectedVersion": 1, "idempotencyKey": "" }),
    "VALIDATION_FAILED"
)]
#[case::consistency(
    json!({ "id": ROUTE, "expectedVersion": 1, "consistency": "PROPAGATED" }),
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn an_invalid_update_input_fails_before_the_command(
    #[case] input: serde_json::Value,
    #[case] expected: &str,
) {
    let (state, commands, ..) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &update_mutation(),
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, "PRECONDITION_FAILED")]
#[case::unknown(|| IamError::NotFound, "NOT_FOUND")]
#[case::system_entry(|| IamError::SystemEntry, "CONFLICT")]
#[case::forbidden(|| IamError::Forbidden, "FORBIDDEN")]
#[tokio::test]
async fn a_refused_update_is_its_graphql_code(
    #[case] refusal: fn() -> IamError,
    #[case] expected: &str,
) {
    let (state, ..) = scenario(Answers {
        update: Err(refusal),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &update_mutation(),
        json!({ "input": { "id": ROUTE, "expectedVersion": 1, "streaming": true } }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[tokio::test]
async fn a_deleted_route_reports_its_final_version_and_dispatches_the_command() {
    let (state, commands, _queries, asked) = scenario(Answers {
        receipt: receipt_at(2, Some(9))
            .with_propagation(PropagationOutcome::Published { offset: 4 }),
        ..Answers::default()
    });
    let variables = json!({ "input": {
        "id": ROUTE,
        "expectedVersion": 1,
        "idempotencyKey": "delete-route",
        "consistency": "PUBLISHED",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, DELETE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteRoute": {
            "id": ROUTE,
            "version": 2,
            "policyVersion": 9,
            "propagation": { "status": "PUBLISHED" },
        } })
    );
    assert_eq!(commands.dispatched(), ["DeleteRouteCommand"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent[0].route_id, route_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
    assert!(sent[0].idempotency.is_some());
}

#[rstest]
#[case::no_version(json!({ "id": ROUTE }), "PRECONDITION_REQUIRED")]
#[case::id(json!({ "id": "nope", "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[case::key(
    json!({ "id": ROUTE, "expectedVersion": 1, "idempotencyKey": "" }),
    "VALIDATION_FAILED"
)]
#[case::consistency(
    json!({ "id": ROUTE, "expectedVersion": 1, "consistency": "PROPAGATED" }),
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn an_invalid_deletion_input_fails_before_the_command(
    #[case] input: serde_json::Value,
    #[case] expected: &str,
) {
    let (state, commands, ..) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        DELETE,
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, "PRECONDITION_FAILED")]
#[case::unknown(|| IamError::NotFound, "NOT_FOUND")]
#[case::system_entry(|| IamError::SystemEntry, "CONFLICT")]
#[tokio::test]
async fn a_refused_deletion_is_its_graphql_code(
    #[case] refusal: fn() -> IamError,
    #[case] expected: &str,
) {
    let (state, ..) = scenario(Answers {
        delete: Err(refusal),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        DELETE,
        json!({ "input": { "id": ROUTE, "expectedVersion": 1 } }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[test]
fn the_route_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::InputType as _;

    use crate::graphql::route::{CreateRouteInput, DeleteRouteInput, UpdateRouteInput};

    let create =
        CreateRouteInput::parse(Some(Value::from_json(created()["input"].clone()).unwrap()))
            .unwrap();
    let update = UpdateRouteInput::parse(Some(
        Value::from_json(json!({ "id": ROUTE, "expectedVersion": 1, "streaming": true })).unwrap(),
    ))
    .unwrap();
    let delete = DeleteRouteInput::parse(Some(
        Value::from_json(json!({ "id": ROUTE, "expectedVersion": 2 })).unwrap(),
    ))
    .unwrap();

    assert_eq!(create.host, "app.example.test");
    assert_eq!(update.streaming, Some(true));
    assert_eq!(update.expected_version, Some(1));
    assert_eq!(delete.id.as_str(), ROUTE);
    assert_eq!(delete.expected_version, Some(2));
    assert!(CreateRouteInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(UpdateRouteInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(DeleteRouteInput::parse(Some(Value::Boolean(true))).is_err());
    let mut wrong_create = created()["input"].clone();
    wrong_create["consistency"] = json!(true);
    let wrong_last = json!({ "id": ROUTE, "consistency": true });
    assert!(CreateRouteInput::parse(Some(Value::from_json(wrong_create).unwrap())).is_err());
    assert!(UpdateRouteInput::parse(Some(Value::from_json(wrong_last.clone()).unwrap())).is_err());
    assert!(DeleteRouteInput::parse(Some(Value::from_json(wrong_last).unwrap())).is_err());
}

#[tokio::test]
async fn a_route_with_a_cors_policy_returns_the_policy() {
    use iam_domain::{CorsDraft, RouteFields};
    use test_support::route::route_draft;

    let mut draft = route_draft(
        "app.example.test",
        "/api/orders/{id}",
        &[HttpMethod::Get],
        "core",
        upstream_id(),
    );
    draft.cors = Some(CorsDraft {
        origins: vec!["https://app.example.test".to_owned()],
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        headers: vec!["x-a".to_owned()],
        allow_credentials: true,
        max_age_seconds: 600,
    });
    let mut stored = route(1);
    stored.fields = RouteFields::new(&draft).unwrap();
    let (state, ..) = scenario(Answers {
        route: Ok(Some(stored)),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        "query($id: ID!) { route(id: $id) \
         { cors { origins methods headers allowCredentials maxAgeSeconds } } }",
        json!({ "id": ROUTE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "route": { "cors": {
            "origins": ["https://app.example.test"],
            "methods": ["GET", "POST"],
            "headers": ["x-a"],
            "allowCredentials": true,
            "maxAgeSeconds": 600,
        } } })
    );
}

#[tokio::test]
async fn a_failing_read_of_a_route_a_page_or_a_replay_is_an_internal_error() {
    let storage: crate::fixtures::Refusal = || IamError::Storage("disk on fire".into());
    let (route_state, ..) = scenario(Answers {
        route: Err(storage),
        ..Answers::default()
    });
    let (page_state, ..) = scenario(Answers {
        page: Err(storage),
        ..Answers::default()
    });
    let (replay_state, commands, ..) = scenario(Answers {
        replay: Err(storage),
        ..Answers::default()
    });
    let mut keyed = created();
    keyed["input"]["idempotencyKey"] = json!("create-route");

    let route = run(
        &schema(Some(route_state)),
        Caller::Valid,
        ROUTE_BY_ID,
        json!({ "id": ROUTE }),
    )
    .await;
    let page = run(&schema(Some(page_state)), Caller::Valid, ROUTES, json!({})).await;
    let replay = run(
        &schema(Some(replay_state)),
        Caller::Valid,
        &create_mutation(),
        keyed,
    )
    .await;

    for response in [&route, &page, &replay] {
        assert_eq!(
            error_code(response),
            Some(code_of("INTERNAL_SERVER_ERROR")),
            "{:?}",
            response.errors
        );
    }
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[test]
fn the_cors_and_filter_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::InputType as _;

    use crate::graphql::route::{CorsPolicyInput, RouteFilterInput};

    let cors = CorsPolicyInput::parse(Some(
        Value::from_json(json!({ "origins": ["https://a.test"], "maxAgeSeconds": 60 })).unwrap(),
    ))
    .unwrap();
    let filter = RouteFilterInput::parse(Some(
        Value::from_json(json!({ "host": "a.test", "service": "core" })).unwrap(),
    ))
    .unwrap();

    assert_eq!(cors.origins, ["https://a.test"]);
    assert_eq!(cors.max_age_seconds, Some(60));
    assert_eq!(filter.host.as_deref(), Some("a.test"));
    assert_eq!(filter.service.as_deref(), Some("core"));
    assert!(CorsPolicyInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(RouteFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for wrong in [
        json!({ "origins": true }),
        json!({ "origins": ["https://a.test"], "maxAgeSeconds": true }),
    ] {
        assert!(CorsPolicyInput::parse(Some(Value::from_json(wrong).unwrap())).is_err());
    }
    for wrong in [json!({ "host": true }), json!({ "service": true })] {
        assert!(RouteFilterInput::parse(Some(Value::from_json(wrong).unwrap())).is_err());
    }
}
