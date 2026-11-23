//! The steps of the activation scenarios of GraphQL specifications: the catalogue entries that a
//! scenario stores beforehand and the entries and grants that an activation leaves behind.

use cucumber::{given, then};

use crate::world::AppWorld;

/// The active GraphQL catalogue entries of the service.
const ACTIVE_ENTRIES_OF_SERVICE: &str =
    "SELECT count(*) FROM iam_graphql_permissions WHERE active AND service = $1";

/// The grants of a role that an activation orphaned.
const ORPHANED_GRANTS_OF_ROLE: &str = "SELECT count(*) FROM iam_role_permissions \
     WHERE role_id = $1::text::uuid AND NOT active AND orphaned_at IS NOT NULL";

/// The grants of a role that are active.
const ACTIVE_GRANTS_OF_ROLE: &str =
    "SELECT count(*) FROM iam_role_permissions WHERE role_id = $1::text::uuid AND active";

/// The active catalogue entry of a key that is sensitive.
const SENSITIVE_ENTRY: &str = "SELECT count(*) FROM iam_graphql_permissions \
     WHERE permission_key = $1 AND sensitive AND active";

/// The active catalogue entry of a key that is not sensitive.
const PLAIN_ENTRY: &str = "SELECT count(*) FROM iam_graphql_permissions \
     WHERE permission_key = $1 AND NOT sensitive AND active";

#[given(expr = "the catalogue holds the inactive sensitive key {string}")]
async fn inactive_sensitive_entry(world: &mut AppWorld, key: String) {
    world.seed_inactive_catalogue_entry(&key, true).await;
}

#[then(
    expr = "the catalogue of the service {string} should hold {int} active GraphQL permission(s)"
)]
async fn catalogue_holds_entries(world: &mut AppWorld, service: String, count: i64) {
    assert_eq!(
        world.count(ACTIVE_ENTRIES_OF_SERVICE, &service).await,
        count
    );
}

#[then(expr = "the seeded role should hold {int} orphaned grant(s)")]
async fn role_holds_orphaned_grants(world: &mut AppWorld, count: i64) {
    let role = world.seeded_role().to_owned();
    assert_eq!(world.count(ORPHANED_GRANTS_OF_ROLE, &role).await, count);
}

#[then(expr = "the seeded role should hold {int} active grant(s)")]
async fn role_holds_active_grants(world: &mut AppWorld, count: i64) {
    let role = world.seeded_role().to_owned();
    assert_eq!(world.count(ACTIVE_GRANTS_OF_ROLE, &role).await, count);
}

#[then(expr = "the key {string} should be an active catalogue entry that is sensitive")]
async fn key_is_active_and_sensitive(world: &mut AppWorld, key: String) {
    assert_eq!(world.count(SENSITIVE_ENTRY, &key).await, 1);
}

#[then(expr = "the key {string} should be an active catalogue entry that is not sensitive")]
async fn key_is_active_and_plain(world: &mut AppWorld, key: String) {
    assert_eq!(world.count(PLAIN_ENTRY, &key).await, 1);
}
