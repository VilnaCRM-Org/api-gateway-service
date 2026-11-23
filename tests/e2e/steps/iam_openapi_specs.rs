//! The steps of the IAM `OpenAPI` specification scenarios: the versions that a scenario left in
//! its database. The oversized-body and the created-then-found steps are shared with the GraphQL
//! specification scenarios.

use cucumber::{given, then};

use crate::world::AppWorld;

/// The versions of the service.
const VERSIONS_OF_SERVICE: &str = "SELECT count(*) FROM iam_openapi_specs WHERE service = $1";

#[then(expr = "the service {string} should have {int} OpenAPI specification version(s)")]
async fn service_has_versions(world: &mut AppWorld, service: String, count: i64) {
    assert_eq!(world.count(VERSIONS_OF_SERVICE, &service).await, count);
}

#[given("the remembered OpenAPI specification is active")]
async fn remembered_specification_is_active(world: &mut AppWorld) {
    world.activate_remembered_openapi_spec().await;
}
