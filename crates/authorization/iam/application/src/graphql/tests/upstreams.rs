use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{EntityVersion, PropagationOutcome, UpstreamProtocol};
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::list_upstreams::{ListUpstreamsQuery, UpstreamPage};
use crate::upstream_fixtures::{
    Answers, UPSTREAM, actor, receipt, receipt_at, recorded, scenario, upstream, upstream_id,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const FIELDS: &str = "id name namespace service catalogService forwardCredentials port protocol \
    connectTimeoutMs responseTimeoutMs concurrencyLimit retryBudgetPercent \
    outlierConsecutiveErrors system version createdAt updatedAt";

fn create_mutation() -> String {
    format!(
        "mutation($input: CreateUpstreamInput!) {{ createUpstream(input: $input) \
         {{ {FIELDS} propagation {{ status policyVersion }} }} }}"
    )
}

fn update_mutation() -> String {
    format!(
        "mutation($input: UpdateUpstreamInput!) {{ updateUpstream(input: $input) \
         {{ {FIELDS} }} }}"
    )
}

const DELETE: &str = "mutation($input: DeleteUpstreamInput!) { deleteUpstream(input: $input) \
    { id version policyVersion propagation { status } } }";
const UPSTREAM_BY_ID: &str = "query($id: ID!) { upstream(id: $id) { id name version } }";
const UPSTREAMS: &str = "query($first: Int, $after: String) \
    { upstreams(first: $first, after: $after) { items { id name version } nextCursor } }";

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
        "name": "core",
        "namespace": "platform",
        "service": "core-service",
        "catalogService": "core",
        "port": 8080,
        "protocol": "h2c",
    } })
}

fn upstream_json(version: i64) -> serde_json::Value {
    json!({
        "id": UPSTREAM,
        "name": "core",
        "namespace": "platform",
        "service": "core-service",
        "catalogService": "core",
        "forwardCredentials": false,
        "port": 8080,
        "protocol": "h2c",
        "connectTimeoutMs": 250,
        "responseTimeoutMs": 10_000,
        "concurrencyLimit": 256,
        "retryBudgetPercent": 10,
        "outlierConsecutiveErrors": 5,
        "system": false,
        "version": version,
        "createdAt": "2027-01-15T08:00:00.000000Z",
        "updatedAt": "2027-01-15T08:05:00.000000Z",
    })
}

#[tokio::test]
async fn a_created_upstream_returns_the_same_data_as_over_rest() {
    let (state, commands, _queries, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        &create_mutation(),
        created(),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let mut expected = upstream_json(1);
    expected["propagation"] = json!(null);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "createUpstream": expected })
    );
    assert_eq!(commands.dispatched(), ["CreateUpstreamCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].name, "core");
    assert_eq!(sent[0].settings.protocol, UpstreamProtocol::H2c);
    assert_eq!(sent[0].settings.connect_timeout_ms, 250);
    assert_eq!(sent[0].settings.outlier_threshold, 5);
    assert!(!sent[0].settings.forward_credentials);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn every_optional_member_of_the_input_reaches_the_command() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "name": "core",
        "namespace": "platform",
        "service": "core-service",
        "catalogService": "core",
        "forwardCredentials": true,
        "port": 9090,
        "protocol": "http1",
        "connectTimeoutMs": 500,
        "responseTimeoutMs": 20_000,
        "concurrencyLimit": 64,
        "retryBudgetPercent": 25,
        "outlierConsecutiveErrors": 3,
        "idempotencyKey": "create-core",
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
    let settings = &recorded(&asked.commands)[0].settings;
    assert!(settings.forward_credentials);
    assert_eq!(settings.port, 9090);
    assert_eq!(settings.protocol, UpstreamProtocol::Http1);
    assert_eq!(settings.connect_timeout_ms, 500);
    assert_eq!(settings.response_timeout_ms, 20_000);
    assert_eq!(settings.concurrency_limit, 64);
    assert_eq!(settings.retry_budget_percent, 25);
    assert_eq!(settings.outlier_threshold, 3);
    assert_eq!(recorded(&asked.replays).len(), 1);
    assert_eq!(
        recorded(&asked.commands)[0]
            .idempotency
            .as_ref()
            .map(|request| request.key.as_str().to_owned()),
        Some("create-core".to_owned())
    );
}

#[tokio::test]
async fn a_pending_write_reports_its_propagation() {
    let answers = Answers {
        receipt: receipt(Some(5)).with_propagation(PropagationOutcome::CommittedPending),
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

    assert_eq!(
        response.data.into_json().unwrap()["createUpstream"]["propagation"],
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
#[case::empty_name(json!({ "name": "" }), "\"name\"")]
#[case::long_namespace(json!({ "namespace": "n".repeat(64) }), "\"namespace\"")]
#[case::empty_service(json!({ "service": "" }), "\"service\"")]
#[case::empty_catalog_service(json!({ "catalogService": "" }), "\"catalogService\"")]
#[case::protocol(json!({ "protocol": "quic" }), "\"protocol\"")]
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
#[case::duplicate(|| IamError::Conflict, "CONFLICT")]
#[case::system_entry(|| IamError::SystemEntry, "CONFLICT")]
#[case::forbidden(|| IamError::Forbidden, "FORBIDDEN")]
#[case::invalid(
    || IamError::from(vec![iam_domain::InvalidUpstream::PortRange]),
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
async fn an_upstream_is_read_by_id_and_an_unknown_one_is_null() {
    let (state, ..) = scenario(Answers {
        upstream: Ok(Some(upstream(4))),
        ..Answers::default()
    });
    let (unknown, ..) = scenario(Answers {
        upstream: Ok(None),
        ..Answers::default()
    });

    let found = run(
        &schema(Some(state)),
        Caller::Valid,
        UPSTREAM_BY_ID,
        json!({ "id": UPSTREAM }),
    )
    .await;
    let missing = run(
        &schema(Some(unknown)),
        Caller::Valid,
        UPSTREAM_BY_ID,
        json!({ "id": UPSTREAM }),
    )
    .await;

    assert_eq!(
        found.data.into_json().unwrap(),
        json!({ "upstream": { "id": UPSTREAM, "name": "core", "version": 4 } })
    );
    assert_eq!(
        missing.data.into_json().unwrap(),
        json!({ "upstream": null })
    );
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_or_a_missing_caller_fails_the_read() {
    let (state, ..) = scenario(Answers::default());
    let schema = schema(Some(state));

    let invalid = run(
        &schema,
        Caller::Valid,
        UPSTREAM_BY_ID,
        json!({ "id": "nope" }),
    )
    .await;
    let anonymous = run(
        &schema,
        Caller::Absent,
        UPSTREAM_BY_ID,
        json!({ "id": UPSTREAM }),
    )
    .await;

    assert_eq!(error_code(&invalid), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&invalid), ["\"id\""]);
    assert_eq!(error_code(&anonymous), Some(code_of("UNAUTHENTICATED")));
}

#[tokio::test]
async fn a_page_of_upstreams_lists_its_items_and_its_cursor() {
    let (state, _commands, _queries, asked) = scenario(Answers {
        page: Ok(UpstreamPage {
            upstreams: vec![upstream(1)],
            next_after: Some(upstream_id()),
        }),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        UPSTREAMS,
        json!({ "first": 1, "after": UPSTREAM }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "upstreams": {
            "items": [{ "id": UPSTREAM, "name": "core", "version": 1 }],
            "nextCursor": UPSTREAM,
        } })
    );
    assert_eq!(
        recorded(&asked.lists),
        [ListUpstreamsQuery {
            limit: 1,
            after: Some(upstream_id())
        }]
    );
}

#[tokio::test]
async fn a_list_without_arguments_asks_for_the_first_page_of_30() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, UPSTREAMS, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&asked.lists),
        [ListUpstreamsQuery {
            limit: 30,
            after: None
        }]
    );
}

#[rstest]
#[case::zero(json!({ "first": 0 }), "\"limit\"")]
#[case::cursor(json!({ "after": "nope" }), "\"after\"")]
#[tokio::test]
async fn an_invalid_page_argument_is_a_validation_failure(
    #[case] variables: serde_json::Value,
    #[case] property: &str,
) {
    let (state, ..) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, UPSTREAMS, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
}

#[tokio::test]
async fn an_updated_upstream_returns_the_new_version_and_dispatches_the_patch() {
    let (state, commands, _queries, asked) = scenario(Answers {
        receipt: receipt_at(2, Some(8)),
        upstream: Ok(Some(upstream(2))),
        ..Answers::default()
    });
    let variables = json!({ "input": {
        "id": UPSTREAM,
        "expectedVersion": 1,
        "port": 9090,
        "protocol": "http1",
        "idempotencyKey": "update-core",
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
        json!({ "updateUpstream": upstream_json(2) })
    );
    assert_eq!(commands.dispatched(), ["UpdateUpstreamCommand"]);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].upstream_id, upstream_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].patch.port, Some(9090));
    assert_eq!(sent[0].patch.protocol, Some(UpstreamProtocol::Http1));
    assert_eq!(sent[0].patch.namespace, None);
    assert!(sent[0].idempotency.is_some());
}

#[tokio::test]
async fn every_member_of_an_update_reaches_the_patch() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "id": UPSTREAM,
        "expectedVersion": 1,
        "name": "core",
        "namespace": "edge",
        "service": "core-v2",
        "catalogService": "payment",
        "forwardCredentials": true,
        "connectTimeoutMs": 500,
        "responseTimeoutMs": 20_000,
        "concurrencyLimit": 64,
        "retryBudgetPercent": 25,
        "outlierConsecutiveErrors": 3,
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
    assert_eq!(patch.name.as_deref(), Some("core"));
    assert_eq!(patch.namespace.as_deref(), Some("edge"));
    assert_eq!(patch.service_name.as_deref(), Some("core-v2"));
    assert_eq!(patch.catalog_service.as_deref(), Some("payment"));
    assert_eq!(patch.forward_credentials, Some(true));
    assert_eq!(patch.connect_timeout_ms, Some(500));
    assert_eq!(patch.response_timeout_ms, Some(20_000));
    assert_eq!(patch.concurrency_limit, Some(64));
    assert_eq!(patch.retry_budget_percent, Some(25));
    assert_eq!(patch.outlier_threshold, Some(3));
}

#[rstest]
#[case::no_version(json!({ "id": UPSTREAM }), "PRECONDITION_REQUIRED")]
#[case::version_below_one(json!({ "id": UPSTREAM, "expectedVersion": 0 }), "PRECONDITION_FAILED")]
#[case::id(json!({ "id": "nope", "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[case::protocol(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "protocol": "quic" }),
    "VALIDATION_FAILED"
)]
#[case::name(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "name": "" }),
    "VALIDATION_FAILED"
)]
#[case::key(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "idempotencyKey": "" }),
    "VALIDATION_FAILED"
)]
#[case::consistency(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "consistency": "PROPAGATED" }),
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
        json!({ "input": { "id": UPSTREAM, "expectedVersion": 1, "port": 9090 } }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[tokio::test]
async fn a_deleted_upstream_reports_its_final_version_and_dispatches_the_command() {
    let (state, commands, _queries, asked) = scenario(Answers {
        receipt: receipt_at(2, Some(9))
            .with_propagation(PropagationOutcome::Published { offset: 4 }),
        ..Answers::default()
    });
    let variables = json!({ "input": {
        "id": UPSTREAM,
        "expectedVersion": 1,
        "idempotencyKey": "delete-core",
        "consistency": "PUBLISHED",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, DELETE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteUpstream": {
            "id": UPSTREAM,
            "version": 2,
            "policyVersion": 9,
            "propagation": { "status": "PUBLISHED" },
        } })
    );
    assert_eq!(commands.dispatched(), ["DeleteUpstreamCommand"]);
    let sent = recorded(&asked.deletions);
    assert_eq!(sent[0].upstream_id, upstream_id());
    assert_eq!(sent[0].expected, EntityVersion::INITIAL);
    assert_eq!(sent[0].actor, actor());
    assert!(sent[0].idempotency.is_some());
}

#[rstest]
#[case::no_version(json!({ "id": UPSTREAM }), "PRECONDITION_REQUIRED")]
#[case::id(json!({ "id": "nope", "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[case::key(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "idempotencyKey": "" }),
    "VALIDATION_FAILED"
)]
#[case::consistency(
    json!({ "id": UPSTREAM, "expectedVersion": 1, "consistency": "PROPAGATED" }),
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
#[case::referenced(|| IamError::ReferencedByRoute, "CONFLICT")]
#[case::stale(|| IamError::PreconditionFailed, "PRECONDITION_FAILED")]
#[case::unknown(|| IamError::NotFound, "NOT_FOUND")]
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
        json!({ "input": { "id": UPSTREAM, "expectedVersion": 1 } }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[test]
fn the_upstream_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::InputType as _;

    use crate::graphql::upstream::{CreateUpstreamInput, DeleteUpstreamInput, UpdateUpstreamInput};

    let create =
        CreateUpstreamInput::parse(Some(Value::from_json(created()["input"].clone()).unwrap()))
            .unwrap();
    let update = UpdateUpstreamInput::parse(Some(
        Value::from_json(json!({ "id": UPSTREAM, "expectedVersion": 1, "port": 9090 })).unwrap(),
    ))
    .unwrap();
    let delete = DeleteUpstreamInput::parse(Some(
        Value::from_json(json!({ "id": UPSTREAM, "expectedVersion": 2 })).unwrap(),
    ))
    .unwrap();

    assert_eq!(create.name, "core");
    assert_eq!(create.port, 8080);
    assert_eq!(update.port, Some(9090));
    assert_eq!(update.expected_version, Some(1));
    assert_eq!(delete.id.as_str(), UPSTREAM);
    assert_eq!(delete.expected_version, Some(2));
    assert!(CreateUpstreamInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(UpdateUpstreamInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(DeleteUpstreamInput::parse(Some(Value::Boolean(true))).is_err());
    let mut wrong_create = created()["input"].clone();
    wrong_create["consistency"] = json!(true);
    let wrong_last = json!({ "id": UPSTREAM, "consistency": true });
    assert!(CreateUpstreamInput::parse(Some(Value::from_json(wrong_create).unwrap())).is_err());
    assert!(
        UpdateUpstreamInput::parse(Some(Value::from_json(wrong_last.clone()).unwrap())).is_err()
    );
    assert!(DeleteUpstreamInput::parse(Some(Value::from_json(wrong_last).unwrap())).is_err());
}
