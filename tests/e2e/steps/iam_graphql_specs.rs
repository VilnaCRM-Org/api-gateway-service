//! The steps of the IAM GraphQL specification scenarios: oversized bodies and the versions that a
//! scenario left in its database.

use cucumber::{given, then, when};
use serde_json::Value;

use crate::world::AppWorld;

/// The versions of the service.
const VERSIONS_OF_SERVICE: &str = "SELECT count(*) FROM iam_graphql_specs WHERE service = $1";

/// A JSON document of exactly `size` bytes: one string member padded with `a`.
fn padded_document(size: usize) -> String {
    let frame = r#"{"padding":""}"#.len();
    format!(
        r#"{{"padding":"{}"}}"#,
        "a".repeat(size.saturating_sub(frame))
    )
}

#[when(expr = "{word} request is sent to {string} with a JSON body of {int} bytes")]
async fn request_is_sent_with_sized_body(
    world: &mut AppWorld,
    method: String,
    path: String,
    size: usize,
) {
    let body = padded_document(size);
    world
        .send(&method, &path, Some("application/json"), &body)
        .await;
}

#[then(expr = "the service {string} should have {int} GraphQL specification version(s)")]
async fn service_has_versions(world: &mut AppWorld, service: String, count: i64) {
    assert_eq!(world.count(VERSIONS_OF_SERVICE, &service).await, count);
}

#[then("the last two responses should be the created version and then the same version found")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn created_then_found_the_same_version(world: &mut AppWorld) {
    let [.., created, found] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    assert_eq!((created.status, found.status), (201, 200));
    assert_eq!(created.json(), found.json());
}

#[given("the remembered GraphQL specification is active")]
async fn remembered_specification_is_active(world: &mut AppWorld) {
    world.activate_remembered_graphql_spec().await;
}

#[then(expr = "the JSON pointer {string} should be the seeded role")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn pointer_is_the_seeded_role(world: &mut AppWorld, pointer: String) {
    let role = world.seeded_role().to_owned();
    let json = world.reply().json();
    assert_eq!(
        json.pointer(&pointer).and_then(Value::as_str),
        Some(role.as_str()),
        "body: {}",
        world.reply().body
    );
}
