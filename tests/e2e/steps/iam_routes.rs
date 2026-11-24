//! The steps of the IAM route scenarios: the upstreams and routes that exist, requests that name
//! an upstream by its name, and the rows that a committed or refused change leaves in the scenario
//! database.

use std::time::Duration;

use cucumber::gherkin::Step;
use cucumber::{given, then, when};
use serde_json::json;

use crate::world::AppWorld;

/// The REST collection of the upstreams.
const UPSTREAMS: &str = "/api/upstreams";

/// The REST collection of the routes.
const ROUTES: &str = "/api/routes";

/// The text of a request that stands for the id of the named upstream.
const UPSTREAM_TOKEN: &str = "UPSTREAM";

/// How often a step reads the audit log while it waits for the writer.
const POLL: Duration = Duration::from_millis(100);

/// How many times a step reads before it gives up: the writer flushes every second.
const POLLS: u32 = 30;

/// The id of the upstream with the name that is not deleted.
const UPSTREAM_ID: &str =
    "SELECT id::text FROM iam_upstreams WHERE name = $1 AND deleted_at IS NULL";

/// The routes of the host that are not deleted.
const ROUTES_OF_HOST: &str =
    "SELECT count(*) FROM iam_routes WHERE host = $1 AND deleted_at IS NULL";

/// The state records of the route that hold its configuration.
const HOLDING_RECORDS: &str = "SELECT count(*) FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'route/' || $1 AND payload IS NOT NULL";

/// The route when the newest of its state records is a tombstone.
const TOMBSTONES: &str = "SELECT count(*) FROM (SELECT payload FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'route/' || $1 \
    ORDER BY position DESC LIMIT 1) AS newest WHERE payload IS NULL";

/// The rejected audit records of the action that the route-scope guard refused.
const ROUTE_SCOPE_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
    WHERE outcome = 'rejected' AND action = $1 AND reason = 'route_scope.denied'";

/// The rejected audit records of the action that refused a system entry.
const SYSTEM_ENTRY_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
    WHERE outcome = 'rejected' AND action = $1 AND reason = 'system_entry'";

/// The committed audit records of the action whose after-summary holds the text.
const SUMMARY_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
    WHERE outcome = 'committed' AND action || '|' || after_summary LIKE $1";

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

#[given(expr = "an upstream exists with name {string} of the catalogue service {string}")]
async fn upstream_exists(world: &mut AppWorld, name: String, catalog_service: String) {
    let body = json!({
        "name": name,
        "namespace": "platform",
        "service": format!("{name}-service"),
        "catalogService": catalog_service,
        "port": 8080,
        "protocol": "h2c",
    })
    .to_string();
    world
        .send("POST", UPSTREAMS, Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[given(
    expr = "a route exists on host {string} with pattern {string} and methods {string} for the upstream {string}"
)]
async fn route_exists(
    world: &mut AppWorld,
    host: String,
    pattern: String,
    methods: String,
    upstream: String,
) {
    let methods: Vec<&str> = methods.split(',').map(str::trim).collect();
    let body = json!({
        "host": host,
        "methods": methods,
        "pathPattern": pattern,
        "service": "core",
        "upstreamId": upstream_id(world, &upstream).await,
    })
    .to_string();
    world
        .send("POST", ROUTES, Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[given(
    expr = "a system route exists on host {string} with pattern {string} for the system upstream {string}"
)]
async fn system_route_exists(
    world: &mut AppWorld,
    host: String,
    pattern: String,
    upstream: String,
) {
    world.seed_system_route(&host, &pattern, &upstream).await;
}

#[when(expr = "POST request is sent to {string} for the upstream {string} with body:")]
async fn post_for_the_upstream(world: &mut AppWorld, step: &Step, path: String, upstream: String) {
    let text = step
        .docstring
        .as_deref()
        .expect("the step has a doc string");
    let body = text.replace(UPSTREAM_TOKEN, &upstream_id(world, &upstream).await);
    world
        .send("POST", &path, Some("application/json"), &body)
        .await;
}

#[when(expr = "the GraphQL operation is sent for the upstream {string}:")]
async fn graphql_for_the_upstream(world: &mut AppWorld, step: &Step, upstream: String) {
    let text = step
        .docstring
        .as_deref()
        .expect("the step has a doc string");
    let query = text.replace(UPSTREAM_TOKEN, &upstream_id(world, &upstream).await);
    let body = json!({ "query": query }).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

#[then(expr = "the routes of the host {string} should number {int}")]
async fn routes_of_the_host(world: &mut AppWorld, host: String, count: i64) {
    assert_eq!(world.count(ROUTES_OF_HOST, &host).await, count);
}

#[then("the state record of the remembered route should hold its configuration")]
async fn state_record_holds_the_configuration(world: &mut AppWorld) {
    let id = world.remembered_id().to_owned();
    assert_eq!(world.count(HOLDING_RECORDS, &id).await, 1);
}

#[then("the state record of the remembered route should be a tombstone")]
async fn state_record_is_a_tombstone(world: &mut AppWorld) {
    let id = world.remembered_id().to_owned();
    assert_eq!(world.count(TOMBSTONES, &id).await, 1);
}

/// Reads the count until it is `expected` or the writer had its time.
async fn wait_for_count(world: &mut AppWorld, statement: &'static str, value: &str, expected: i64) {
    let mut found = world.count(statement, value).await;
    for _ in 0..POLLS {
        if found == expected {
            break;
        }
        tokio::time::sleep(POLL).await;
        found = world.count(statement, value).await;
    }
    assert_eq!(found, expected, "{value}");
}

#[then(
    expr = "the audit log should hold {int} route-scope-denied {string} record(s) within one second"
)]
async fn route_scope_records(world: &mut AppWorld, count: i64, action: String) {
    wait_for_count(world, ROUTE_SCOPE_RECORDS, &action, count).await;
}

#[then(expr = "the audit log should hold {int} system-entry {string} record(s) in a second")]
async fn system_entry_records(world: &mut AppWorld, count: i64, action: String) {
    wait_for_count(world, SYSTEM_ENTRY_RECORDS, &action, count).await;
}

#[then(expr = "the audit log should hold {int} committed {string} record(s) that name {string}")]
async fn summary_records(world: &mut AppWorld, count: i64, action: String, text: String) {
    let pattern = format!("{action}|%{text}%");
    assert_eq!(world.count(SUMMARY_RECORDS, &pattern).await, count);
}
