//! The steps of the route configuration scenarios: requests that name an upstream or the stored
//! version of a host's set, generated sets of many routes, and the rows that an applied set leaves
//! in the scenario database.

use cucumber::gherkin::Step;
use cucumber::{then, when};
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
