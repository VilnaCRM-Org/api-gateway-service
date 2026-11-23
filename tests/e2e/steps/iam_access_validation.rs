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

#[then(expr = "both access validations should deny the keys {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn validations_should_deny_the_keys(world: &mut AppWorld, keys: String) {
    let expected: Vec<&str> = keys.split(", ").collect();
    for decision in decisions(world) {
        assert_eq!(decision["denied"], json!(expected), "{decision}");
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

#[when(expr = "a check of a GraphQL document of {int} aliases is sent over REST and GraphQL")]
async fn check_of_aliased_document(world: &mut AppWorld, count: u32) {
    let selections = (0..count)
        .map(|number| format!("a{number}: invoice {{ id }} "))
        .collect::<Vec<_>>()
        .concat();
    let document = format!("{{ {selections}}}");
    let rest = json!({
        "credential": "{token}",
        "service": "billing",
        "graphql": {"document": document},
        "requestId": "req-aliases"
    });
    world
        .send(
            "POST",
            "/api/access-validations",
            Some("application/json"),
            &rest.to_string(),
        )
        .await;
    let query = format!(
        "{{ validateAccess(input: {{credential: \"{{token}}\", service: \"billing\", \
         graphql: {{document: {document:?}}}, requestId: \"req-aliases\"}}) \
         {{ decision reason denied scopes {{ all projects }} subject {{ id kind }} decisionId \
         policyVersion requestId }} }}"
    );
    let body = json!({"query": query}).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

/// The selection of the batch operation over GraphQL: every member that REST answers.
const BATCH_QUERY: &str = "query($inputs: [ValidateAccessInput!]!) { validateAccessBatch(inputs: $inputs) \
     { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion \
     requestId } }";

/// A check of the shape that both interfaces take.
fn check(credential: &str, service: &str, method: &str, path: &str, request_id: &str) -> Value {
    json!({
        "credential": credential,
        "service": service,
        "rest": {"method": method, "path": path},
        "requestId": request_id
    })
}

/// Sends the checks as a batch over REST, then over GraphQL.
async fn send_batch(world: &mut AppWorld, checks: &[Value]) {
    let rest = json!({ "checks": checks });
    world
        .send(
            "POST",
            "/api/access-validations/batch",
            Some("application/json"),
            &rest.to_string(),
        )
        .await;
    let graphql = json!({"query": BATCH_QUERY, "variables": {"inputs": checks}});
    world
        .send(
            "POST",
            "/api/graphql",
            Some("application/json"),
            &graphql.to_string(),
        )
        .await;
}

/// The results of the last two replies, REST first, without the decision identifiers; the
/// identifiers are checked to be present and different within each reply.
fn batch_results(world: &AppWorld) -> [Vec<Value>; 2] {
    let [.., rest, graphql] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    let from_rest = rest.json().get("results").cloned();
    let from_graphql = graphql.json().pointer("/data/validateAccessBatch").cloned();
    [
        results_without_ids(from_rest, &rest.body, true),
        results_without_ids(from_graphql, &graphql.body, false),
    ]
}

/// The results of one reply as comparable objects, after checking that no decision identifier
/// repeats within it.
fn results_without_ids(results: Option<Value>, body: &str, rest: bool) -> Vec<Value> {
    let Some(Value::Array(results)) = results else {
        panic!("no batch results in: {body}");
    };
    let mut seen = Vec::new();
    for result in &results {
        let id = result["decisionId"]
            .as_str()
            .unwrap_or_else(|| panic!("no decision id in: {body}"));
        assert!(!seen.contains(&id), "a decision id repeats: {id}");
        seen.push(id);
    }
    results
        .into_iter()
        .map(|result| comparable(result, rest))
        .collect()
}

#[when("a batch of mixed checks is sent over REST and GraphQL")]
async fn batch_of_mixed_checks(world: &mut AppWorld) {
    let checks = [
        check("{token}", "billing", "GET", "/invoices/42", "batch-0"),
        check("{token}", "billing", "POST", "/refunds", "batch-1"),
        check("{token}", "billing", "GET", "/unknown", "batch-2"),
        check("{token}", "billing", "GET", "/invoices/../42", "batch-3"),
        check("{token}", "billing", "FETCH", "/invoices/42", "batch-4"),
        check("not-a-token", "billing", "GET", "/invoices/42", "batch-5"),
        check("{token}", "shipping", "GET", "/parcels", "batch-6"),
    ];
    send_batch(world, &checks).await;
}

#[when(expr = "a batch of {int} checks is sent over REST and GraphQL")]
async fn batch_of_many_checks(world: &mut AppWorld, count: u32) {
    let checks: Vec<Value> = (0..count)
        .map(|number| {
            check(
                "{token}",
                "billing",
                "GET",
                "/invoices/42",
                &format!("batch-{number}"),
            )
        })
        .collect();
    send_batch(world, &checks).await;
}

#[when(
    expr = "a batch of {int} checks that alternate between the subject token and an invalid one is sent over REST and GraphQL"
)]
async fn batch_of_two_credentials(world: &mut AppWorld, count: u32) {
    let checks: Vec<Value> = (0..count)
        .map(|number| {
            let credential = if number % 2 == 0 {
                "{token}"
            } else {
                "not-a-token"
            };
            check(
                credential,
                "billing",
                "GET",
                "/invoices/42",
                &format!("batch-{number}"),
            )
        })
        .collect();
    send_batch(world, &checks).await;
}

#[then(
    expr = "the REST and GraphQL batch results should be the same and have the reasons {string}"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn batch_results_have_the_reasons(world: &mut AppWorld, reasons: String) {
    let [rest, graphql] = batch_results(world);
    assert_eq!(rest, graphql);
    let expected: Vec<&str> = reasons.split(", ").collect();
    let actual: Vec<&str> = rest
        .iter()
        .map(|result| result["reason"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(actual, expected);
    for (position, result) in rest.iter().enumerate() {
        assert_eq!(result["requestId"], format!("batch-{position}"), "{result}");
        assert_eq!(result["decision"] == "allow", result["reason"] == "allowed");
    }
}

#[then(
    expr = "the REST and GraphQL batch results should be the same and alternate {string} and {string}"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn batch_results_alternate(world: &mut AppWorld, even: String, odd: String) {
    let [rest, graphql] = batch_results(world);
    assert_eq!(rest, graphql);
    for (position, result) in rest.iter().enumerate() {
        let expected = if position % 2 == 0 { &even } else { &odd };
        assert_eq!(result["reason"], expected.as_str(), "{position}: {result}");
    }
}

#[then(expr = "both batches should have {int} results")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn both_batches_have_results(world: &mut AppWorld, count: usize) {
    for results in batch_results(world) {
        assert_eq!(results.len(), count);
    }
}

#[then(expr = "the GraphQL batch should fail with the code {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn graphql_batch_fails(world: &mut AppWorld, code: String) {
    let [.., _rest, graphql] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    assert_eq!(
        graphql.json().pointer("/errors/0/extensions/code"),
        Some(&Value::String(code)),
        "body: {}",
        graphql.body
    );
}
