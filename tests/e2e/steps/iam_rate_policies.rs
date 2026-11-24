//! The steps of the IAM rate-policy scenarios: a rate policy that exists, a route that applies it
//! and the rows that a committed change leaves in the scenario database.

use cucumber::{given, then};

use crate::world::AppWorld;

/// The REST collection of the rate policies.
const RATE_POLICIES: &str = "/api/rate-policies";

/// The body of a rate policy named `name`.
const BODY: &str = r#"{"name": "NAME", "key": "subject_route", "limit": 100, "periodMs": 60000, "burst": 20, "fallback": "divided"}"#;

/// The rate policies that are not deleted with the name.
const POLICIES_NAMED: &str =
    "SELECT count(*) FROM iam_rate_policies WHERE name = $1 AND deleted_at IS NULL";

/// The state records of the remembered rate policy that hold its configuration.
const HOLDING_RECORDS: &str = "SELECT count(*) FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'ratepolicy/' || $1 AND payload IS NOT NULL";

/// The remembered rate policy when the newest of its state records is a tombstone.
const TOMBSTONES: &str = "SELECT count(*) FROM (SELECT payload FROM iam_outbox \
    WHERE kind = 'state' AND record_key = 'ratepolicy/' || $1 \
    ORDER BY position DESC LIMIT 1) AS newest WHERE payload IS NULL";

#[given(expr = "a rate policy exists with name {string}")]
async fn rate_policy_exists(world: &mut AppWorld, name: String) {
    let body = BODY.replace("NAME", &name);
    world
        .send("POST", RATE_POLICIES, Some("application/json"), &body)
        .await;
    assert_eq!(world.reply().status, 201, "body: {}", world.reply().body);
}

#[given("a route applies the rate policy")]
async fn route_applies_the_rate_policy(world: &mut AppWorld) {
    world.seed_route_with_remembered_rate_policy().await;
}

#[then(expr = "the rate policy {string} should be stored once")]
async fn rate_policy_is_stored_once(world: &mut AppWorld, name: String) {
    assert_eq!(world.count(POLICIES_NAMED, &name).await, 1);
}

#[then(expr = "the rate policy {string} should be stored {int} times")]
async fn rate_policy_is_stored_times(world: &mut AppWorld, name: String, times: i64) {
    assert_eq!(world.count(POLICIES_NAMED, &name).await, times);
}

#[then("the state record of the rate policy should hold its configuration")]
async fn state_record_holds_the_configuration(world: &mut AppWorld) {
    let id = world.remembered_id().to_owned();
    assert_eq!(world.count(HOLDING_RECORDS, &id).await, 1);
}

#[then("the state record of the rate policy should be a tombstone")]
async fn state_record_is_a_tombstone(world: &mut AppWorld) {
    let id = world.remembered_id().to_owned();
    assert_eq!(world.count(TOMBSTONES, &id).await, 1);
}
