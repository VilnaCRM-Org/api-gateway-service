use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::PropagationOutcome;
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::route_configuration_fixtures::{
    Answers, configuration, declared, preview, receipt_of, recorded, scenario,
};
use crate::route_fixtures::{HOST, UPSTREAM, actor};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const APPLY: &str = "mutation($input: ApplyRouteConfigurationInput!) \
    { applyRouteConfiguration(input: $input) { host dryRun version routeCount revocation unchanged \
    added { methods pathPattern changedFields } changed { methods pathPattern changedFields } \
    removed { methods pathPattern changedFields } policyVersion propagation { status policyVersion } } }";
const READ: &str = "query($host: String!) { routeConfiguration(host: $host) { host version \
    routes { methods pathPattern service upstreamId graphql streaming anonymous enforcement \
    bodyLimitBytes requestTimeoutMs idleTimeoutMs retryPolicy ratePolicyIds \
    cors { origins methods headers allowCredentials maxAgeSeconds } } } }";

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

fn declaration(path: &str) -> serde_json::Value {
    json!({
        "methods": ["GET"],
        "pathPattern": path,
        "service": "core",
        "upstreamId": UPSTREAM,
    })
}

fn input(paths: &[&str], extra: &serde_json::Value) -> serde_json::Value {
    let mut input = json!({
        "host": HOST,
        "routes": paths.iter().map(|path| declaration(path)).collect::<Vec<_>>(),
        "expectedVersion": configuration().version.value(),
    });
    if let (Some(input), Some(extra)) = (input.as_object_mut(), extra.as_object()) {
        input.extend(extra.clone());
    }
    json!({ "input": input })
}

#[tokio::test]
async fn the_configuration_of_a_host_lists_its_routes_and_its_version() {
    let (state, _commands, queries, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        READ,
        json!({ "host": HOST }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let read = &data["routeConfiguration"];
    assert_eq!(read["host"], json!(HOST));
    assert_eq!(read["version"], json!(configuration().version.value()));
    assert_eq!(read["routes"][0]["pathPattern"], json!("/a"));
    assert_eq!(read["routes"][0]["methods"], json!(["GET"]));
    assert_eq!(read["routes"][0]["upstreamId"], json!(UPSTREAM));
    assert_eq!(read["routes"][0]["enforcement"], json!("enforce"));
    assert_eq!(read["routes"][0]["retryPolicy"], json!("none"));
    assert_eq!(read["routes"][0]["cors"], json!(null));
    assert_eq!(read["routes"][1]["pathPattern"], json!("/b"));
    assert_eq!(queries.asked(), ["GetRouteConfigurationQuery"]);
    assert_eq!(recorded(&asked.configurations)[0].host, HOST);
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::refused(Caller::Refused)]
#[tokio::test]
async fn a_read_without_an_authenticated_caller_is_unauthenticated(#[case] caller: Caller) {
    let (state, ..) = scenario(Answers::default());

    let response = run(&schema(Some(state)), caller, READ, json!({ "host": HOST })).await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
}

#[tokio::test]
async fn an_application_reports_the_diff_the_version_and_the_policy_version() {
    let (state, commands, queries, asked) = scenario(Answers {
        receipt: receipt_of(5, Some(8))
            .with_propagation(PropagationOutcome::Published { offset: 4 }),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        APPLY,
        input(&["/a", "/b", "/c"], &json!({ "consistency": "PUBLISHED" })),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "applyRouteConfiguration": {
            "host": HOST,
            "dryRun": false,
            "version": 5,
            "routeCount": 3,
            "revocation": false,
            "unchanged": 2,
            "added": [{ "methods": ["GET"], "pathPattern": "/c", "changedFields": [] }],
            "changed": [],
            "removed": [],
            "policyVersion": 8,
            "propagation": { "status": "PUBLISHED", "policyVersion": 8 },
        } })
    );
    assert_eq!(commands.dispatched(), ["ApplyRouteConfigurationCommand"]);
    assert_eq!(
        queries.asked(),
        ["PreviewRouteConfigurationQuery", "GetChangeReceiptQuery"]
    );
    let sent = recorded(&asked.applies);
    assert_eq!(sent[0].host, HOST);
    assert_eq!(sent[0].routes.len(), 3);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].expected, configuration().version);
}

#[tokio::test]
async fn a_dry_run_reports_the_diff_and_dispatches_nothing() {
    let (state, commands, queries, _asked) = scenario(Answers {
        preview: Ok(preview(vec![declared("/b"), declared("/c")])),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        APPLY,
        input(&["/b", "/c"], &json!({ "dryRun": true })),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    let applied = &data["applyRouteConfiguration"];
    assert_eq!(applied["dryRun"], json!(true));
    assert_eq!(applied["version"], json!(configuration().version.value()));
    assert_eq!(applied["revocation"], json!(true));
    assert_eq!(applied["added"][0]["pathPattern"], json!("/c"));
    assert_eq!(applied["removed"][0]["pathPattern"], json!("/a"));
    assert_eq!(applied["policyVersion"], json!(null));
    assert_eq!(applied["propagation"], json!(null));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["PreviewRouteConfigurationQuery"]);
}

#[tokio::test]
async fn a_set_that_changes_nothing_dispatches_nothing() {
    let (state, commands, ..) = scenario(Answers {
        preview: Ok(preview(vec![declared("/a"), declared("/b")])),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        APPLY,
        input(&["/a", "/b"], &json!({})),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_declaration_with_every_member_is_read() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let route = json!({
        "methods": ["GET", "POST"],
        "pathPattern": "/full",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": true,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 2048,
        "requestTimeoutMs": 5000,
        "idleTimeoutMs": 6000,
        "retryPolicy": "idempotent",
        "ratePolicyIds": [],
        "cors": {
            "origins": ["https://app.example.test"],
            "methods": ["GET"],
            "headers": ["x-token"],
            "allowCredentials": true,
            "maxAgeSeconds": 60,
        },
    });
    let variables = json!({ "input": {
        "host": HOST,
        "routes": [route],
        "expectedVersion": configuration().version.value(),
    } });

    let response = run(&schema(Some(state)), Caller::Valid, APPLY, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let sent = recorded(&asked.previews);
    let draft = &sent[0].routes[0];
    assert!(draft.flags.graphql() && draft.flags.streaming() && draft.flags.anonymous());
    assert_eq!(draft.body_limit, 2048);
    assert_eq!(draft.request_timeout_ms, 5000);
    assert_eq!(draft.idle_timeout_ms, 6000);
    assert_eq!(draft.cors.as_ref().unwrap().max_age_seconds, 60);
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::refused(Caller::Refused)]
#[tokio::test]
async fn an_application_without_an_authenticated_caller_is_unauthenticated(#[case] caller: Caller) {
    let (state, commands, ..) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        caller,
        APPLY,
        input(&["/a"], &json!({})),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::no_version(
    json!({ "input": { "host": HOST, "routes": [] } }),
    "PRECONDITION_REQUIRED"
)]
#[case::version_below_one(
    json!({ "input": { "host": HOST, "routes": [], "expectedVersion": 0 } }),
    "PRECONDITION_FAILED"
)]
#[case::method(
    json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [{
        "methods": ["TRACE"], "pathPattern": "/a", "service": "core", "upstreamId": UPSTREAM,
    }] } }),
    "VALIDATION_FAILED"
)]
#[case::enforcement(
    json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [{
        "methods": ["GET"], "pathPattern": "/a", "service": "core", "upstreamId": UPSTREAM,
        "enforcement": "maybe",
    }] } }),
    "VALIDATION_FAILED"
)]
#[case::retry(
    json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [{
        "methods": ["GET"], "pathPattern": "/a", "service": "core", "upstreamId": UPSTREAM,
        "retryPolicy": "always",
    }] } }),
    "VALIDATION_FAILED"
)]
#[case::upstream(
    json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [{
        "methods": ["GET"], "pathPattern": "/a", "service": "core", "upstreamId": "nope",
    }] } }),
    "VALIDATION_FAILED"
)]
#[case::mode(
    json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [], "consistency": "PROPAGATED" } }),
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn an_input_that_cannot_be_read_is_refused_before_anything_is_asked(
    #[case] variables: serde_json::Value,
    #[case] expected: &str,
) {
    let (state, commands, queries, _asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, APPLY, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_declaration_that_cannot_be_read_names_its_position() {
    let (state, ..) = scenario(Answers::default());
    let variables = json!({ "input": { "host": HOST, "expectedVersion": 1, "routes": [
        declaration("/a"),
        { "methods": ["TRACE"], "pathPattern": "/b", "service": "core", "upstreamId": UPSTREAM },
    ] } });

    let response = run(&schema(Some(state)), Caller::Valid, APPLY, variables).await;

    assert_eq!(
        violation_paths(&response),
        vec![String::from("\"routes[1].methods\"")]
    );
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, "PRECONDITION_FAILED")]
#[case::system_entry(|| IamError::SystemEntry, "CONFLICT")]
#[case::conflict(
    || IamError::RouteTableConflict { code: "route_table_conflict" },
    "CONFLICT"
)]
#[case::forbidden(|| IamError::Forbidden, "FORBIDDEN")]
#[case::too_many(
    || IamError::invalid_property("routes", "Too many.", "max_items"),
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn a_refused_application_is_its_graphql_code(
    #[case] refusal: fn() -> IamError,
    #[case] expected: &str,
) {
    let (state, ..) = scenario(Answers {
        preview: Err(refusal),
        ..Answers::default()
    });

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        APPLY,
        input(&["/a"], &json!({})),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[test]
fn the_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::InputType as _;

    use crate::graphql::route_configuration::{
        ApplyRouteConfigurationInput, RouteDeclarationInput,
    };

    let declared =
        RouteDeclarationInput::parse(Some(Value::from_json(declaration("/a")).unwrap())).unwrap();
    let applied = ApplyRouteConfigurationInput::parse(Some(
        Value::from_json(input(&["/a", "/b"], &json!({ "dryRun": true }))["input"].clone())
            .unwrap(),
    ))
    .unwrap();

    assert_eq!(declared.path_pattern, "/a");
    assert_eq!(declared.methods, ["GET"]);
    assert_eq!(applied.host, HOST);
    assert_eq!(applied.routes.len(), 2);
    assert_eq!(applied.dry_run, Some(true));
    assert!(RouteDeclarationInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(ApplyRouteConfigurationInput::parse(Some(Value::Boolean(true))).is_err());
    for (field, wrong) in [("pathPattern", json!(true)), ("cors", json!(true))] {
        let mut wrong_route = declaration("/a");
        wrong_route[field] = wrong;
        let parsed = RouteDeclarationInput::parse(Some(Value::from_json(wrong_route).unwrap()));
        assert!(parsed.is_err(), "{field}");
    }
    for (field, wrong) in [("dryRun", json!("yes")), ("consistency", json!(true))] {
        let mut wrong_set = json!({ "host": HOST, "routes": [] });
        wrong_set[field] = wrong;
        let parsed =
            ApplyRouteConfigurationInput::parse(Some(Value::from_json(wrong_set).unwrap()));
        assert!(parsed.is_err(), "{field}");
    }
}
