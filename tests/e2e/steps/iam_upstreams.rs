//! The steps of the IAM upstream scenarios: an upstream that exists, a route that references it,
//! the callers of `RouteScopeGuard` and the rows that a committed or refused change leaves in the
//! scenario database.

use std::time::Duration;

use cucumber::{given, then};
use serde_json::Value;

use crate::world::AppWorld;

/// The REST collection of the upstreams.
const UPSTREAMS: &str = "/api/upstreams";

/// The body of an upstream named `NAME`.
const BODY: &str = r#"{"name": "NAME", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}"#;

/// How often a step reads the audit log while it waits for the writer.
const POLL: Duration = Duration::from_millis(100);

/// How many times a step reads before it gives up: the writer flushes every second.
const POLLS: u32 = 30;

/// The upstreams that are not deleted with the name.
const UPSTREAMS_NAMED: &str =
    "SELECT count(*) FROM iam_upstreams WHERE name = $1 AND deleted_at IS NULL";

/// The state records of the upstream with the name that hold its configuration.
const HOLDING_RECORDS: &str = "SELECT count(*) FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'upstream/' || $1 AND payload IS NOT NULL";

/// The upstream with the name when the newest of its state records is a tombstone.
const TOMBSTONES: &str = "SELECT count(*) FROM (SELECT payload FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'upstream/' || $1 \
    ORDER BY position DESC LIMIT 1) AS newest WHERE payload IS NULL";

/// The rejected audit records of the action that the route-scope guard refused: they are written
/// in the request, not by the buffered writer.
const ROUTE_SCOPE_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
    WHERE outcome = 'rejected' AND action = $1 AND reason = 'route_scope.denied'";

/// The rejected audit records of the action that refused a system entry: the buffered writer
/// appends them.
const SYSTEM_ENTRY_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
    WHERE outcome = 'rejected' AND action = $1 AND reason = 'system_entry'";

#[given("a caller authenticated as an administrator that holds iam:route:core only")]
fn caller_as_the_route_scoped_administrator(world: &mut AppWorld) {
    world.authenticate_as_route_scoped_administrator();
}

#[given(expr = "an upstream exists with name {string}")]
async fn upstream_exists(world: &mut AppWorld, name: String) {
    let body = BODY.replace("NAME", &name);
    world
        .send("POST", UPSTREAMS, Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[given(expr = "a system upstream exists with name {string}")]
async fn system_upstream_exists(world: &mut AppWorld, name: String) {
    world.seed_upstream(&name, "iam", true).await;
}

#[given(expr = "a route references the upstream {string}")]
async fn route_references_the_upstream(world: &mut AppWorld, name: String) {
    world.seed_route_to_upstream(&name).await;
}

#[then(expr = "the upstream {string} should be stored once")]
async fn upstream_is_stored_once(world: &mut AppWorld, name: String) {
    assert_eq!(world.count(UPSTREAMS_NAMED, &name).await, 1);
}

#[then(expr = "the upstream {string} should be stored {int} times")]
async fn upstream_is_stored_times(world: &mut AppWorld, name: String, times: i64) {
    assert_eq!(world.count(UPSTREAMS_NAMED, &name).await, times);
}

#[then(expr = "the state record of the upstream {string} should hold its configuration")]
async fn state_record_holds_the_configuration(world: &mut AppWorld, name: String) {
    assert_eq!(world.count(HOLDING_RECORDS, &name).await, 1);
}

#[then(expr = "the state record of the upstream {string} should be a tombstone")]
async fn state_record_is_a_tombstone(world: &mut AppWorld, name: String) {
    assert_eq!(world.count(TOMBSTONES, &name).await, 1);
}

#[then(expr = "the audit log should hold {int} route-scope-denied {string} record(s)")]
async fn route_scope_records(world: &mut AppWorld, count: i64, action: String) {
    assert_eq!(world.count(ROUTE_SCOPE_RECORDS, &action).await, count);
}

#[then(expr = "the audit log should hold {int} system-entry {string} record(s) within one second")]
async fn system_entry_records(world: &mut AppWorld, count: i64, action: String) {
    let mut found = world.count(SYSTEM_ENTRY_RECORDS, &action).await;
    for _ in 0..POLLS {
        if found == count {
            break;
        }
        tokio::time::sleep(POLL).await;
        found = world.count(SYSTEM_ENTRY_RECORDS, &action).await;
    }
    assert_eq!(found, count, "{action}");
}

#[then(expr = "the JSON boolean at {string} should be {word}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn boolean_should_be(world: &mut AppWorld, pointer: String, expected: String) {
    let expected = match expected.as_str() {
        "true" => true,
        "false" => false,
        other => panic!("{other:?} is neither true nor false"),
    };
    let json = world.reply().json();
    assert_eq!(
        json.pointer(&pointer),
        Some(&Value::Bool(expected)),
        "body: {}",
        world.reply().body
    );
}
