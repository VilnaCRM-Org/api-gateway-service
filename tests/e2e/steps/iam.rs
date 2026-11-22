//! The steps of the IAM context.

use cucumber::then;
use test_support::policy_epoch::seeded_policy_epoch;

use crate::world::AppWorld;

#[then("the IAM policy epoch should be the seeded one")]
async fn policy_epoch_should_be_the_seeded_one(world: &mut AppWorld) {
    assert_eq!(world.policy_epoch().await, seeded_policy_epoch());
}
