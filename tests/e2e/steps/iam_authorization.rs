//! The steps of the authorization scenarios: the rejected attempts that a refused request leaves
//! in the audit log, which the per-replica writer appends within one second.

use std::time::Duration;

use cucumber::then;

use crate::world::AppWorld;

/// How often a step reads the audit log while it waits for the writer.
const POLL: Duration = Duration::from_millis(100);

/// How many times a step reads before it gives up: the writer flushes every second.
const POLLS: u32 = 30;

/// The rejected audit records of the action with the reason `forbidden`.
const FORBIDDEN_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events \
     WHERE outcome = 'rejected' AND action = $1 AND reason = 'forbidden'";

/// Every rejected audit record, whatever the action; the value is not used.
const ANY_REJECTED_RECORDS: &str = "SELECT count(*) FROM iam_security_audit_events WHERE outcome = 'rejected' AND $1::text = $1::text";

/// Reads `statement` until it counts `expected` or the writer had its time.
async fn wait_for_count(world: &mut AppWorld, statement: &'static str, value: &str, expected: i64) {
    let mut found = world.count(statement, value).await;
    for _ in 0..POLLS {
        if found == expected {
            break;
        }
        tokio::time::sleep(POLL).await;
        found = world.count(statement, value).await;
    }
    assert_eq!(found, expected, "{value}");
}

#[then(expr = "the audit log should hold {int} forbidden {string} record(s) within one second")]
async fn forbidden_records(world: &mut AppWorld, count: i64, action: String) {
    wait_for_count(world, FORBIDDEN_RECORDS, &action, count).await;
}

#[then("the audit log should hold no rejected record after the writer ran")]
async fn no_rejected_record(world: &mut AppWorld) {
    // The writer flushes every second; two flushes later a record of the refused request would be
    // there.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(world.count(ANY_REJECTED_RECORDS, "").await, 0);
}
