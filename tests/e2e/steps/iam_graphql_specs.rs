//! The steps of the IAM GraphQL specification scenarios: oversized bodies and the versions that a
//! scenario left in its database.

use cucumber::{then, when};

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
