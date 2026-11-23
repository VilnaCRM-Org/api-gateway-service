//! The steps of the first-administrator scenarios: the bootstrap as the operator runs it, and the
//! audit records that a refused change leaves.

use cucumber::{given, then};

use crate::tokens::USER_ID;
use crate::world::AppWorld;

/// The rejected audit records with the action and the reason, joined by `|`.
const REJECTED_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
     WHERE outcome = 'rejected' AND action = split_part($1, '|', 1) \
     AND reason = split_part($1, '|', 2)";

/// The active global assignments of `iam-platform-admin`.
const ADMINISTRATORS: &str = "SELECT count(*) FROM iam_user_roles assignments \
     JOIN iam_roles roles ON roles.id = assignments.role_id \
     WHERE roles.name = $1 AND assignments.scope_kind = 'global' \
     AND assignments.revoked_at IS NULL";

#[given("the first administrator is bootstrapped")]
async fn first_administrator(world: &mut AppWorld) {
    world.bootstrap_administrator(USER_ID).await;
}

#[then(
    expr = "the audit log should hold {int} rejected {string} record(s) with the reason {string}"
)]
async fn rejected_records(world: &mut AppWorld, count: i64, action: String, reason: String) {
    let value = format!("{action}|{reason}");
    assert_eq!(world.count(REJECTED_RECORDS, &value).await, count);
}

#[then(expr = "the role {string} should have {int} active global assignment(s)")]
async fn active_global_assignments(world: &mut AppWorld, role: String, count: i64) {
    assert_eq!(world.count(ADMINISTRATORS, &role).await, count);
}
