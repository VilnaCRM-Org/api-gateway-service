//! The steps of the bulk operation scenarios: a role with many assignments, the wait for the
//! runner and the rows that the chunks leave in the scenario database.

use cucumber::{given, then, when};

use crate::world::AppWorld;

/// The most revoked-assignment events that one policy version holds: the assignments one chunk
/// revoked.
const MAX_ENTITIES_PER_VERSION: &str = "SELECT coalesce(max(n), 0) FROM (\
     SELECT count(*) AS n FROM iam_outbox WHERE kind = 'event' \
     AND event_type = 'iam.user_role.revoked' GROUP BY policy_version) AS versions \
     WHERE $1 = $1";

/// The distinct policy versions of the revoked-assignment events.
const REVOKING_VERSIONS: &str = "SELECT count(DISTINCT policy_version) FROM iam_outbox \
     WHERE kind = 'event' AND event_type = 'iam.user_role.revoked' AND $1 = $1";

#[given(expr = "the seeded role has {int} assignments")]
async fn seeded_role_has_assignments(world: &mut AppWorld, count: i64) {
    world.seed_assignments(count).await;
}

#[when("the bulk operation runner has finished every bulk operation")]
async fn runner_finishes(world: &mut AppWorld) {
    world.wait_for_bulk_operations().await;
}

#[then(expr = "no version should revoke more than {int} assignments")]
async fn no_version_revokes_more(world: &mut AppWorld, limit: i64) {
    assert!(world.count(MAX_ENTITIES_PER_VERSION, "").await <= limit);
}

#[then(expr = "the assignments should be revoked in {int} versions")]
async fn revoked_in_versions(world: &mut AppWorld, versions: i64) {
    assert_eq!(world.count(REVOKING_VERSIONS, "").await, versions);
}
