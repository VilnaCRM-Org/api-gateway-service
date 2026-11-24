//! The steps of the policy resync scenarios: the log epoch of the policy and the state rows that a
//! resync leaves in the scenario database.

use cucumber::then;

use crate::world::AppWorld;

/// The log epoch of the policy epoch row.
const LOG_EPOCH: &str = "SELECT log_epoch FROM iam_policy_epoch WHERE id = 1 AND $1 = $1";

/// The roles that are not deleted and have no state row under the log epoch.
const ROLES_WITHOUT_A_ROW: &str = "SELECT count(*) FROM iam_roles AS stored_role \
     WHERE stored_role.deleted_at IS NULL AND NOT EXISTS (\
         SELECT 1 FROM iam_outbox AS state_row WHERE state_row.kind = 'state' \
         AND state_row.record_key = 'role/' || stored_role.id::text AND state_row.log_epoch = ($1::text)::bigint)";

/// The state rows of the log epoch whose version does not lie above every version of the older
/// epochs.
const ROWS_NOT_ABOVE_THE_OLDER_EPOCHS: &str = "SELECT count(*) FROM iam_outbox AS state_row \
     WHERE state_row.kind = 'state' AND state_row.log_epoch = ($1::text)::bigint \
     AND state_row.policy_version <= (\
         SELECT coalesce(max(older.policy_version), 0) FROM iam_outbox AS older \
         WHERE older.kind = 'state' AND older.log_epoch < ($1::text)::bigint)";

/// One when the digest of the policy epoch row is the digest of the newest head row.
const HEAD_DIGEST_IS_THE_EPOCH_DIGEST: &str = "SELECT count(*) FROM iam_policy_epoch \
     WHERE id = 1 AND digest = (\
         SELECT digest_after FROM iam_outbox WHERE kind = 'state' AND record_key = '__head' \
         ORDER BY position DESC LIMIT 1) AND $1 = $1";

#[then(expr = "the policy log epoch should be {int}")]
async fn log_epoch_is(world: &mut AppWorld, epoch: i64) {
    assert_eq!(world.count(LOG_EPOCH, "").await, epoch);
}

#[then(expr = "every stored role should have a state row under the log epoch {int}")]
async fn every_role_is_republished(world: &mut AppWorld, epoch: i64) {
    assert_eq!(
        world.count(ROLES_WITHOUT_A_ROW, &epoch.to_string()).await,
        0
    );
}

#[then(expr = "the state rows of the log epoch {int} should lie above every earlier version")]
async fn rows_lie_above_the_older_epochs(world: &mut AppWorld, epoch: i64) {
    assert_eq!(
        world
            .count(ROWS_NOT_ABOVE_THE_OLDER_EPOCHS, &epoch.to_string())
            .await,
        0
    );
}

#[then("the newest head digest should equal the digest of the policy epoch")]
async fn the_head_digest_is_the_epoch_digest(world: &mut AppWorld) {
    assert_eq!(world.count(HEAD_DIGEST_IS_THE_EPOCH_DIGEST, "").await, 1);
}
