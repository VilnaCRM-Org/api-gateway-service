//! The steps of the activation scenarios of `OpenAPI` specifications: the REST catalogue entries
//! that a scenario stores beforehand and the entries that an activation leaves behind. The steps
//! about grants and events are shared with the GraphQL activation scenarios.

use cucumber::{given, then};

use crate::world::AppWorld;

/// The active REST catalogue entries of the service.
const ACTIVE_ENTRIES_OF_SERVICE: &str =
    "SELECT count(*) FROM iam_rest_permissions WHERE active AND service = $1";

/// The active REST catalogue entry of a key that is sensitive.
const SENSITIVE_ENTRY: &str = "SELECT count(*) FROM iam_rest_permissions \
     WHERE permission_key = $1 AND sensitive AND active";

/// The active REST catalogue entry of a key that is not sensitive.
const PLAIN_ENTRY: &str = "SELECT count(*) FROM iam_rest_permissions \
     WHERE permission_key = $1 AND NOT sensitive AND active";

#[given(expr = "the catalogue holds the inactive sensitive REST key {string}")]
async fn inactive_sensitive_entry(world: &mut AppWorld, key: String) {
    world.seed_inactive_rest_catalogue_entry(&key, true).await;
}

#[then(expr = "the catalogue of the service {string} should hold {int} active REST permission(s)")]
async fn catalogue_holds_entries(world: &mut AppWorld, service: String, count: i64) {
    assert_eq!(
        world.count(ACTIVE_ENTRIES_OF_SERVICE, &service).await,
        count
    );
}

#[then(expr = "the REST key {string} should be an active catalogue entry that is sensitive")]
async fn key_is_active_and_sensitive(world: &mut AppWorld, key: String) {
    assert_eq!(world.count(SENSITIVE_ENTRY, &key).await, 1);
}

#[then(expr = "the REST key {string} should be an active catalogue entry that is not sensitive")]
async fn key_is_active_and_plain(world: &mut AppWorld, key: String) {
    assert_eq!(world.count(PLAIN_ENTRY, &key).await, 1);
}
