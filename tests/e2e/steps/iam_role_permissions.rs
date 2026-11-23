//! The steps of the IAM role grant scenarios: the replacements that are too large to write out and
//! the audit records that keep the summary of a replacement.

use cucumber::{then, when};
use serde_json::json;

use crate::world::AppWorld;

/// The REST path of the grants of the seeded role.
const SEEDED_ROLE_PERMISSIONS: &str = "/api/roles/{role}/permissions";

/// The committed audit records with the action whose after summary holds a text; the value holds
/// both, separated by `|`.
const RECORDS_WITH_SUMMARY: &str = "SELECT count(*) FROM iam_security_audit_events \
     WHERE outcome = 'committed' AND action = split_part($1, '|', 1) \
     AND strpos(after_summary, split_part($1, '|', 2)) > 0";

/// `count` distinct REST keys of the service `billing`.
fn generated_keys(count: u32) -> Vec<String> {
    (0..count)
        .map(|number| format!("rest:billing:GET /generated/{number}"))
        .collect()
}

#[when(expr = "{int} generated keys replace the grants of the seeded role over REST")]
async fn generated_keys_over_rest(world: &mut AppWorld, count: u32) {
    let body = json!({ "keys": generated_keys(count) }).to_string();
    world
        .send(
            "PUT",
            SEEDED_ROLE_PERMISSIONS,
            Some("application/json"),
            &body,
        )
        .await;
}

#[then(
    expr = "the audit log should hold {int} committed {string} record whose summary holds {string}"
)]
async fn audit_summary_holds(world: &mut AppWorld, count: i64, action: String, text: String) {
    let value = format!("{action}|{text}");
    assert_eq!(world.count(RECORDS_WITH_SUMMARY, &value).await, count);
}
