//! The steps of the IAM role scenarios: role creation, the JSON of the answers, the cursor and the
//! rows that a committed change leaves in the scenario database.

use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::world::AppWorld;

/// The REST collection of the roles.
const ROLES: &str = "/api/roles";

/// The rows of the outbox with the event type.
const OUTBOX_EVENTS: &str =
    "SELECT count(*) FROM iam_outbox WHERE kind = 'event' AND event_type = $1";

/// The committed audit records with the action.
const COMMITTED_RECORDS: &str =
    "SELECT count(*) FROM iam_security_audit_events WHERE outcome = 'committed' AND action = $1";

/// The roles with the name, without regard to case.
const ROLES_NAMED: &str = "SELECT count(*) FROM iam_roles WHERE lower(name) = lower($1)";

#[given(expr = "the idempotency key {string}")]
fn idempotency_key(world: &mut AppWorld, key: String) {
    world.set_idempotency_key(key);
}

#[given(expr = "the If-Match header {string}")]
fn if_match_header(world: &mut AppWorld, value: String) {
    world.set_if_match(value);
}

#[given("the If-Match header is the ETag of the last response")]
fn if_match_is_the_last_etag(world: &mut AppWorld) {
    let etag = world
        .reply()
        .headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .expect("the last response has an ETag")
        .to_owned();
    world.set_if_match(etag);
}

#[given(expr = "a system role exists with name {string}")]
async fn system_role_exists(world: &mut AppWorld, name: String) {
    world.seed_system_role(&name).await;
}

#[given(expr = "a role exists with name {string}")]
async fn role_exists(world: &mut AppWorld, name: String) {
    let body = json!({ "name": name }).to_string();
    world
        .send("POST", ROLES, Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[when(expr = "the cursor at {string} is remembered")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn cursor_is_remembered(world: &mut AppWorld, pointer: String) {
    let json = world.reply().json();
    let cursor = json
        .pointer(&pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no cursor at {pointer}: {json}"))
        .to_owned();
    world.set_cursor(cursor);
}

/// The value of the last response at `pointer`; the whole body's JSON is searched.
fn at(world: &AppWorld, pointer: &str) -> Option<Value> {
    world.reply().json().pointer(pointer).cloned()
}

#[then(expr = "the JSON pointer {string} should equal {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_should_equal_text(world: &mut AppWorld, pointer: String, expected: String) {
    assert_eq!(
        at(world, &pointer),
        Some(Value::String(expected)),
        "body: {}",
        world.reply().body
    );
}

#[then(expr = "the JSON pointer {string} should equal the number {int}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_should_equal_number(world: &mut AppWorld, pointer: String, expected: i64) {
    assert_eq!(
        at(world, &pointer),
        Some(Value::from(expected)),
        "body: {}",
        world.reply().body
    );
}

#[then(expr = "the JSON pointer {string} should be present")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_should_be_present(world: &mut AppWorld, pointer: String) {
    let value = at(world, &pointer);
    assert!(
        value.is_some_and(|value| !value.is_null()),
        "nothing at {pointer}: {}",
        world.reply().body
    );
}

#[then(expr = "the JSON pointer {string} should be absent")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_should_be_absent(world: &mut AppWorld, pointer: String) {
    assert_eq!(at(world, &pointer), None, "body: {}", world.reply().body);
}

#[then(expr = "the JSON pointer {string} should be null")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_should_be_null(world: &mut AppWorld, pointer: String) {
    assert_eq!(
        at(world, &pointer),
        Some(Value::Null),
        "body: {}",
        world.reply().body
    );
}

#[then(expr = "the JSON array at {string} should have {int} items")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn array_should_have_items(world: &mut AppWorld, pointer: String, expected: usize) {
    let value = at(world, &pointer);
    let items = value.as_ref().and_then(Value::as_array).map(Vec::len);
    assert_eq!(items, Some(expected), "body: {}", world.reply().body);
}

#[then("the last two responses should have the same body")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn last_two_responses_are_the_same(world: &mut AppWorld) {
    let [.., first, second] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    assert_eq!(first.json(), second.json());
    assert_eq!(first.status, second.status);
}

#[then(expr = "the role {string} should be stored once")]
async fn role_is_stored_once(world: &mut AppWorld, name: String) {
    assert_eq!(world.count(ROLES_NAMED, &name).await, 1);
}

#[then(expr = "the role {string} should be stored {int} times")]
async fn role_is_stored_times(world: &mut AppWorld, name: String, times: i64) {
    assert_eq!(world.count(ROLES_NAMED, &name).await, times);
}

#[then(expr = "the outbox should hold {int} {string} event(s)")]
async fn outbox_holds_events(world: &mut AppWorld, count: i64, event_type: String) {
    assert_eq!(world.count(OUTBOX_EVENTS, &event_type).await, count);
}

#[then(expr = "the audit log should hold {int} committed {string} record(s)")]
async fn audit_log_holds_records(world: &mut AppWorld, count: i64, action: String) {
    assert_eq!(world.count(COMMITTED_RECORDS, &action).await, count);
}
