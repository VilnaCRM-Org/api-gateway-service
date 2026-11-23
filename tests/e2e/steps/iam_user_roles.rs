//! The steps of the IAM role assignment scenarios: the roles that a scenario seeds, the policy
//! version and the rows that a committed assignment leaves in the scenario database.

use cucumber::{given, then};

use crate::world::AppWorld;

/// The assignments of the subject kind that are not revoked.
const ASSIGNMENTS_OF_KIND: &str =
    "SELECT count(*) FROM iam_user_roles WHERE revoked_at IS NULL AND subject_kind = $1";

/// The outbox events of a type whose payload holds a text; the value holds both, separated by `|`.
const EVENTS_WITH_PAYLOAD: &str = "SELECT count(*) FROM iam_outbox WHERE kind = 'event' \
     AND event_type = split_part($1, '|', 1) AND strpos(payload, split_part($1, '|', 2)) > 0";

#[given(expr = "an assignable role {string}")]
async fn assignable_role(world: &mut AppWorld, name: String) {
    world.seed_role(&name, &[]).await;
}

#[given(expr = "an assignable role {string} that grants {string}")]
async fn assignable_role_with_grants(world: &mut AppWorld, name: String, grants: String) {
    let keys: Vec<String> = grants.split(", ").map(str::to_owned).collect();
    world.seed_role(&name, &keys).await;
}

#[then(expr = "the IAM policy version should be {int}")]
async fn policy_version_is(world: &mut AppWorld, expected: i64) {
    assert_eq!(world.policy_epoch().await.version().value(), expected);
}

#[then(expr = "the store should hold {int} assignment(s) of subject kind {string}")]
async fn assignments_of_kind(world: &mut AppWorld, count: i64, kind: String) {
    assert_eq!(world.count(ASSIGNMENTS_OF_KIND, &kind).await, count);
}

#[then(expr = "the {string} event should carry {string} in its payload")]
async fn event_payload_carries(world: &mut AppWorld, event_type: String, text: String) {
    let value = format!("{event_type}|{text}");
    assert_eq!(world.count(EVENTS_WITH_PAYLOAD, &value).await, 1);
}
