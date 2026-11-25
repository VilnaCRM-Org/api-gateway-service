//! The steps of the route configuration scenarios: requests that name an upstream or the stored
//! version of a host's set, generated sets of many routes, and the rows that an applied set leaves
//! in the scenario database.

use cucumber::gherkin::Step;
use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::world::AppWorld;

/// The text of a request that stands for the id of the named upstream.
const UPSTREAM_TOKEN: &str = "UPSTREAM";

/// The text of a request that stands for the stored version of the set of a host.
const VERSION_TOKEN: &str = "VERSION";

/// The id of the upstream with the name that is not deleted.
const UPSTREAM_ID: &str =
    "SELECT id::text FROM iam_upstreams WHERE name = $1 AND deleted_at IS NULL";

/// The events of the policy version that the newest applied route configuration produced.
const APPLICATION_EVENTS: &str = "SELECT count(*) FROM iam_outbox WHERE kind = 'event' \
    AND policy_version = (SELECT policy_version FROM iam_outbox WHERE kind = 'event' \
    AND event_type = 'iam.route_configuration.applied' ORDER BY position DESC LIMIT 1) \
    AND $1 = $1";

/// The routes whose newest state record is a configuration (`$1` is `configuration`) or a
/// tombstone.
const NEWEST_RECORDS: &str = "SELECT count(*) FROM (SELECT DISTINCT ON (record_key) payload \
    FROM iam_outbox WHERE kind = 'state' AND record_key LIKE 'route/%' \
    ORDER BY record_key, position DESC) AS newest \
    WHERE (payload IS NULL) = ($1 = 'tombstone')";

/// The id of the named upstream.
///
/// # Panics
///
/// When no upstream of the name exists.
async fn upstream_id(world: &mut AppWorld, name: &str) -> String {
    world
        .select_text(UPSTREAM_ID, name)
        .await
        .expect("the upstream exists")
}

/// The version of the stored route set of `host`, as `GET` reports it.
///
/// # Panics
///
/// When the read fails.
async fn stored_version(world: &mut AppWorld, host: &str) -> i64 {
    world
        .send(
            "GET",
            &format!("/api/route-configurations/{host}"),
            None,
            "",
        )
        .await;
    assert_eq!(world.reply().status, 200, "body: {}", world.reply().body);
    world.reply().json()["version"].as_i64().expect("a version")
}

/// The declared routes `/r0` to `/r{count - 1}` of the upstream.
fn generated(count: i64, upstream: &str) -> Vec<Value> {
    (0..count)
        .map(|number| {
            json!({
                "methods": ["GET"],
                "pathPattern": format!("/r{number}"),
                "service": "core",
                "upstreamId": upstream,
            })
        })
        .collect()
}

#[when(expr = "PUT request is sent to {string} for the upstream {string} with body:")]
async fn put_for_the_upstream(world: &mut AppWorld, step: &Step, path: String, upstream: String) {
    let text = step
        .docstring
        .as_deref()
        .expect("the step has a doc string");
    let body = text.replace(UPSTREAM_TOKEN, &upstream_id(world, &upstream).await);
    world
        .send_verbatim("PUT", &path, Some("application/json"), &body)
        .await;
}

#[when(
    expr = "the GraphQL operation is sent for the upstream {string} against the stored set of the host {string}:"
)]
async fn graphql_against_the_stored_set(
    world: &mut AppWorld,
    step: &Step,
    upstream: String,
    host: String,
) {
    let text = step
        .docstring
        .as_deref()
        .expect("the step has a doc string");
    let version = stored_version(world, &host).await;
    let query = text
        .replace(UPSTREAM_TOKEN, &upstream_id(world, &upstream).await)
        .replace(VERSION_TOKEN, &version.to_string());
    let body = json!({ "query": query }).to_string();
    world
        .send_verbatim("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

#[when(expr = "{int} generated routes are put to {string} for the upstream {string}")]
async fn generated_routes_are_put(
    world: &mut AppWorld,
    count: i64,
    path: String,
    upstream: String,
) {
    let upstream = upstream_id(world, &upstream).await;
    let body = json!({ "routes": generated(count, &upstream) }).to_string();
    world
        .send("PUT", &path, Some("application/json"), &body)
        .await;
}

#[when(
    expr = "{int} generated routes are applied over GraphQL to the host {string} for the upstream {string}"
)]
async fn generated_routes_are_applied(
    world: &mut AppWorld,
    count: i64,
    host: String,
    upstream: String,
) {
    let upstream = upstream_id(world, &upstream).await;
    let version = stored_version(world, &host).await;
    let body = json!({
        "query": "mutation($input: ApplyRouteConfigurationInput!) \
            { applyRouteConfiguration(input: $input) { version routeCount } }",
        "variables": { "input": {
            "host": host,
            "expectedVersion": version,
            "routes": generated(count, &upstream),
        } },
    })
    .to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

#[then(expr = "the policy version of the application should hold {int} events")]
async fn application_version_holds_events(world: &mut AppWorld, count: i64) {
    assert_eq!(world.count(APPLICATION_EVENTS, "").await, count);
}

#[then(
    expr = "the newest state records of the routes should hold {int} configurations and {int} tombstones"
)]
async fn newest_records(world: &mut AppWorld, configurations: i64, tombstones: i64) {
    assert_eq!(
        world.count(NEWEST_RECORDS, "configuration").await,
        configurations
    );
    assert_eq!(world.count(NEWEST_RECORDS, "tombstone").await, tombstones);
}

/// The root of the repository, where the reference route configurations are kept.
const REPOSITORY_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// The text of the reference route configuration at `file`, relative to the repository root.
///
/// # Panics
///
/// When the file cannot be read.
fn reference_text(file: &str) -> String {
    std::fs::read_to_string(format!("{REPOSITORY_ROOT}/{file}"))
        .expect("the reference route configuration is readable")
}

/// The `(methods, pathPattern)` pairs of the routes in `document`, methods sorted and joined.
///
/// # Panics
///
/// When a route lacks `methods` or `pathPattern`.
fn route_keys(routes: &Value) -> std::collections::BTreeSet<(String, String)> {
    routes
        .as_array()
        .expect("a list of routes")
        .iter()
        .map(|route| {
            let mut methods: Vec<&str> = route["methods"]
                .as_array()
                .expect("methods")
                .iter()
                .map(|method| method.as_str().expect("a method"))
                .collect();
            methods.sort_unstable();
            (
                methods.join(","),
                route["pathPattern"]
                    .as_str()
                    .expect("a path pattern")
                    .to_owned(),
            )
        })
        .collect()
}

#[given(
    expr = "a credential-forwarding upstream exists with name {string} of the catalogue service {string}"
)]
async fn credential_forwarding_upstream_exists(
    world: &mut AppWorld,
    name: String,
    catalog_service: String,
) {
    let body = json!({
        "name": name,
        "namespace": "platform",
        "service": format!("{name}-service"),
        "catalogService": catalog_service,
        "port": 8080,
        "protocol": "h2c",
        "forwardCredentials": true,
    })
    .to_string();
    world
        .send("POST", "/api/upstreams", Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[when(
    expr = "the reference route configuration {string} is put in a dry run to {string} for the upstream {string}"
)]
async fn reference_configuration_dry_run(
    world: &mut AppWorld,
    file: String,
    path: String,
    upstream: String,
) {
    let body = reference_text(&file).replace(UPSTREAM_TOKEN, &upstream_id(world, &upstream).await);
    world
        .send_verbatim(
            "PUT",
            &format!("{path}?dryRun=true"),
            Some("application/json"),
            &body,
        )
        .await;
}

#[then(
    expr = "the dry run should list exactly the routes of the reference route configuration {string} as added"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn dry_run_lists_the_reference_routes(world: &mut AppWorld, file: String) {
    let declared: Value = serde_json::from_str(&reference_text(&file)).expect("valid JSON");
    let reply = world.reply().json();
    assert_eq!(
        route_keys(&reply["added"]),
        route_keys(&declared["routes"]),
        "body: {}",
        world.reply().body
    );
    assert_eq!(
        reply["added"].as_array().map(Vec::len),
        declared["routes"].as_array().map(Vec::len)
    );
    assert_eq!(reply["changed"].as_array().map(Vec::len), Some(0));
    assert_eq!(reply["removed"].as_array().map(Vec::len), Some(0));
}

#[then(expr = "every route of the reference route configuration {string} should be anonymous")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn every_reference_route_is_anonymous(_world: &mut AppWorld, file: String) {
    let declared: Value = serde_json::from_str(&reference_text(&file)).expect("valid JSON");
    let routes = declared["routes"].as_array().expect("a list of routes");
    assert_ne!(routes.len(), 0);
    for route in routes {
        assert_eq!(
            route["anonymous"],
            Value::Bool(true),
            "route: {}",
            route["pathPattern"]
        );
    }
}
