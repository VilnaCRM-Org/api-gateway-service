//! The steps of the access-validation scenarios: the comparison of the REST and the GraphQL
//! decision of one check and the checks that are too large to write out.

use cucumber::{then, when};
use serde_json::{Map, Value, json};

use crate::world::AppWorld;

/// The decision of the last two replies, REST first, as comparable objects.
///
/// The decision identifier differs between two decisions by design, so it is checked for presence
/// and dropped; GraphQL answers every field of the selection, so its null fields are dropped as
/// REST leaves them out; the scopes take the object form of GraphQL.
fn decisions(world: &AppWorld) -> [Value; 2] {
    let [.., rest, graphql] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    let from_graphql = graphql
        .json()
        .pointer("/data/validateAccess")
        .cloned()
        .unwrap_or(Value::Null);
    [
        comparable(rest.json(), true),
        comparable(from_graphql, false),
    ]
}

fn comparable(decision: Value, rest: bool) -> Value {
    let Value::Object(fields) = decision else {
        panic!("not a decision: {decision}");
    };
    assert!(
        fields.get("decisionId").is_some_and(Value::is_string),
        "no decision id: {fields:?}"
    );
    let mut kept = Map::new();
    for (name, value) in fields {
        if name == "decisionId" || value.is_null() {
            continue;
        }
        if rest && name == "scopes" {
            kept.insert(name, scopes_object(&value));
        } else {
            kept.insert(name, value);
        }
    }
    Value::Object(kept)
}

/// The object form of the scopes of a REST body: the string `all`, or a list of project ids.
fn scopes_object(scopes: &Value) -> Value {
    match scopes {
        Value::String(all) if all == "all" => json!({"all": true, "projects": []}),
        Value::Array(projects) => json!({"all": false, "projects": projects}),
        other @ (Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Object(_)) => panic!("unexpected scopes: {other}"),
    }
}

#[then("the REST and GraphQL access validations should be the same")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_be_the_same(world: &mut AppWorld) {
    let [rest, graphql] = decisions(world);
    assert_eq!(rest, graphql);
}

#[then("both access validations should be an allow for every project")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_allow_every_project(world: &mut AppWorld) {
    for decision in decisions(world) {
        assert_eq!(decision["decision"], "allow", "{decision}");
        assert_eq!(decision["reason"], "allowed", "{decision}");
        assert_eq!(decision["denied"], json!([]), "{decision}");
        assert_eq!(
            decision["scopes"],
            json!({"all": true, "projects": []}),
            "{decision}"
        );
        assert!(decision["subject"]["id"].is_string(), "{decision}");
        assert_eq!(decision["subject"]["kind"], "user", "{decision}");
        assert!(decision["policyVersion"].is_i64(), "{decision}");
    }
}

#[then(expr = "both access validations should be a deny with reason {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_deny(world: &mut AppWorld, reason: String) {
    for decision in decisions(world) {
        assert_eq!(decision["decision"], "deny", "{decision}");
        assert_eq!(decision["reason"], reason.as_str(), "{decision}");
        assert_eq!(
            decision["scopes"],
            json!({"all": false, "projects": []}),
            "{decision}"
        );
    }
}

#[then(expr = "both access validations should deny {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_deny_the_key(world: &mut AppWorld, key: String) {
    for decision in decisions(world) {
        assert_eq!(decision["denied"], json!([key]), "{decision}");
    }
}

#[then(expr = "both access validations should be an allow in the projects {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_allow_projects(world: &mut AppWorld, projects: String) {
    let expected: Vec<&str> = projects.split(", ").collect();
    for decision in decisions(world) {
        assert_eq!(decision["decision"], "allow", "{decision}");
        assert_eq!(
            decision["scopes"],
            json!({"all": false, "projects": expected}),
            "{decision}"
        );
    }
}

#[then(expr = "both access validations should echo the request id {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_echo_the_request_id(world: &mut AppWorld, request_id: String) {
    for decision in decisions(world) {
        assert_eq!(decision["requestId"], request_id.as_str(), "{decision}");
    }
}

#[then(expr = "the REST status of the check should be {int}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn rest_status_of_the_check(world: &mut AppWorld, expected: u16) {
    let [.., rest, _graphql] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    assert_eq!(rest.status, expected, "body: {}", rest.body);
}

#[when(expr = "a check of {int} permission keys is sent over REST and GraphQL")]
async fn check_of_many_keys(world: &mut AppWorld, count: u32) {
    let keys: Vec<String> = (0..count)
        .map(|number| format!("rest:billing:GET /generated/{number}"))
        .collect();
    let rest = json!({
        "credential": "{token}",
        "service": "billing",
        "permissions": keys,
        "requestId": "req-many"
    });
    world
        .send(
            "POST",
            "/api/access-validations",
            Some("application/json"),
            &rest.to_string(),
        )
        .await;
    let list = keys
        .iter()
        .map(|key| format!("{key:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "{{ validateAccess(input: {{credential: \"{{token}}\", service: \"billing\", \
         permissions: [{list}], requestId: \"req-many\"}}) {{ decision reason }} }}"
    );
    let body = json!({"query": query}).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}
