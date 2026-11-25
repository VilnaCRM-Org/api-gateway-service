//! The steps of the access decision query scenarios: decisions pushed to the compose Loki, and
//! searches and reads of them over REST and GraphQL.
//!
//! The compose Loki keeps its data between runs, so every subject name is made unique to the run
//! that pushes it, and a search always names its subject.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use cucumber::{given, when};
use iam_domain::{
    AccessDecision, AccessEntry, AccessLane, AccessLogFilter, AccessLogQuery as _, AccessLogRange,
    AccessLogSearch, AccessLogSink as _, AccessRecord, DecisionReason, SubjectKind,
};
use iam_infrastructure::{
    LokiAccessLogQuery, LokiPushAccessLogSink, LokiQueryTransport, LokiSinkSettings,
};
use serde_json::json;
use service::bootstrap::HyperLokiQueryTransport;
use service::bootstrap::gateway::access_log::LOKI_APP_LABEL;
use service::bootstrap::gateway::access_log::loki_transport::HyperLokiTransport;
use shared_domain::{Clock as _, UuidGenerator as _};
use shared_infrastructure::clock::SystemClock;
use shared_infrastructure::id::UuidV7Generator;

use crate::world::AppWorld;

/// How long a pushed decision may take to become visible to a query.
const VISIBLE_WITHIN: Duration = Duration::from_secs(20);

/// The environment label of the decisions of an end-to-end run.
const ENV_LABEL: &str = "test";

/// The fields that a search or a read selects.
const FIELDS: &str = "id occurredAt method host routeTemplate status upstream subjectId \
    subjectKind decision reason permissionKey denied policyVersion";

/// The suffix that makes the subject names of this run unique.
fn run() -> &'static str {
    static RUN: OnceLock<String> = OnceLock::new();
    RUN.get_or_init(|| {
        let nanos = SystemClock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos();
        format!("{}-{nanos}", std::process::id())
    })
}

/// The subject id that `name` stands for in this run.
fn subject_of(name: &str) -> String {
    format!("{name}-{}", run())
}

/// The value of an environment variable of the end-to-end run.
fn variable(name: &str) -> String {
    optional_variable(name)
        .unwrap_or_else(|| panic!("{name} is not set; run the tests through `make`"))
}

/// The value of an environment variable of the end-to-end run, when it is set.
#[expect(
    clippy::disallowed_methods,
    reason = "the Loki endpoints are the variables that the Loki scenarios read from the environment"
)]
fn optional_variable(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The tenant of the compose Loki.
fn tenant() -> String {
    optional_variable("LOKI_TENANT_ID").unwrap_or_else(|| "iam".to_owned())
}

/// `time` as an RFC 3339 UTC time in whole seconds.
fn rfc3339(time: SystemTime) -> String {
    humantime::format_rfc3339_seconds(time).to_string()
}

/// The range that holds every decision pushed by a scenario: an hour before now to an hour after.
fn range() -> (SystemTime, SystemTime) {
    let now = SystemClock.now();
    (
        now.checked_sub(Duration::from_hours(1)).expect("a clock"),
        now.checked_add(Duration::from_hours(1)).expect("a clock"),
    )
}

/// The decision of `subject`, `offset` milliseconds before now.
fn decision(subject: &str, status: u16, offset: u64) -> AccessRecord {
    let occurred_at = SystemClock
        .now()
        .checked_sub(Duration::from_millis(offset))
        .expect("a clock");
    AccessRecord {
        decision_id: UuidV7Generator.generate(),
        occurred_at,
        method: "GET".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: None,
        route_template: Some("/api/users/{id}".to_owned()),
        status,
        upstream: Some("user-service".to_owned()),
        latency_us: 1_200,
        bytes_in: 0,
        bytes_out: 64,
        request_id: Some("req-e2e".to_owned()),
        subject_id: Some(subject.to_owned()),
        subject_kind: Some(SubjectKind::User),
        decision: AccessDecision::Deny,
        reason: DecisionReason::PermissionMissing,
        permission_key: Some("user:read".to_owned()),
        denied: vec!["user:read".to_owned()],
        project_id: None,
        policy_version: Some(7),
        credential_digest_prefix: Some("deadbeef".to_owned()),
    }
}

/// Pushes `records` to the compose Loki as the audit lane of a gateway does, and waits for the push
/// to be acknowledged.
async fn push(records: Vec<AccessRecord>) {
    let uri = variable("LOKI_PUSH_URL")
        .parse()
        .expect("LOKI_PUSH_URL is a URI");
    let tenant = tenant();
    tokio::task::spawn_blocking(move || {
        let transport = HyperLokiTransport::new(uri, &tenant).expect("a transport");
        let settings = LokiSinkSettings {
            app: LOKI_APP_LABEL.to_owned(),
            env: ENV_LABEL.to_owned(),
            flush_interval: Duration::from_millis(100),
        };
        let sink =
            LokiPushAccessLogSink::start(settings, Arc::new(transport)).expect("a sink thread");
        for record in records {
            sink.write(AccessLane::Audit, &AccessEntry::Record(Box::new(record)));
        }
        sink.flush();
    })
    .await
    .expect("the push thread ended");
}

/// The adapter that reads the compose Loki, as the control plane does.
fn reader() -> LokiAccessLogQuery {
    let tenant = tenant();
    let transport: Arc<dyn LokiQueryTransport> = Arc::new(
        HyperLokiQueryTransport::new(&tenant, Duration::from_secs(5)).expect("a transport"),
    );
    LokiAccessLogQuery::new(
        transport,
        &variable("LOKI_QUERY_URL"),
        LOKI_APP_LABEL,
        ENV_LABEL,
    )
}

/// Waits until the compose Loki returns `count` decisions of `subject`.
async fn wait_for(subject: &str, count: usize) {
    let reader = reader();
    let (from, until) = range();
    let search = AccessLogSearch {
        range: AccessLogRange::new(from, until, Duration::from_hours(2)).expect("a range"),
        filter: AccessLogFilter {
            subject_id: Some(subject.to_owned()),
            ..AccessLogFilter::default()
        },
        cursor: None,
        limit: 500,
    };
    let deadline = tokio::time::Instant::now()
        .checked_add(VISIBLE_WITHIN)
        .expect("a deadline");
    loop {
        let found = reader.search(&search).await.map_or(0, |found| found.len());
        if found >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Loki returned {found} of {count} decisions of {subject} within {VISIBLE_WITHIN:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[given(
    expr = "the compose Loki holds {int} decisions of the subject {string} denied with status {int}"
)]
async fn loki_holds(_world: &mut AppWorld, count: usize, name: String, status: u16) {
    let subject = subject_of(&name);
    let records = (0..count)
        .map(|offset| decision(&subject, status, u64::try_from(offset).expect("a count")))
        .collect();
    push(records).await;
    wait_for(&subject, count).await;
}

#[when(expr = "the access decisions of the subject {string} are searched over REST with {string}")]
async fn search_over_rest(world: &mut AppWorld, name: String, query: String) {
    let (from, until) = range();
    let path = format!(
        "/api/access-decisions?from={}&until={}&subjectId={}&{query}",
        rfc3339(from),
        rfc3339(until),
        subject_of(&name),
    );
    world.send("GET", &path, None, "").await;
}

#[when(
    expr = "the access decisions of the subject {string} are searched over GraphQL with the filter {string}"
)]
async fn search_over_graphql(world: &mut AppWorld, name: String, filter: String) {
    let (from, until) = range();
    let query = format!(
        "{{ accessDecisions(first: 100, filter: {{from: \"{}\", until: \"{}\", subjectId: \"{}\"{}{filter}}}) \
         {{ items {{ {FIELDS} }} nextCursor }} }}",
        rfc3339(from),
        rfc3339(until),
        subject_of(&name),
        if filter.is_empty() { "" } else { ", " },
    );
    let body = json!({ "query": query }).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

#[when("the access decisions are searched over REST without a time range")]
async fn search_without_a_range(world: &mut AppWorld) {
    world.send("GET", "/api/access-decisions", None, "").await;
}

#[when(expr = "the access decisions are searched over REST from {string} until {string}")]
async fn search_over_a_range(world: &mut AppWorld, from: String, until: String) {
    let path = format!("/api/access-decisions?from={from}&until={until}");
    world.send("GET", &path, None, "").await;
}

#[when("the access decisions are searched over GraphQL without a time range")]
async fn graphql_without_a_range(world: &mut AppWorld) {
    let body = json!({ "query": "{ accessDecisions { items { id } } }" }).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}

#[when("the first decision of the last search is read by id over REST")]
async fn first_decision_over_rest(world: &mut AppWorld) {
    let id = world
        .reply()
        .json()
        .pointer("/items/0/id")
        .and_then(serde_json::Value::as_str)
        .expect("the search returned a decision")
        .to_owned();
    world
        .send("GET", &format!("/api/access-decisions/{id}"), None, "")
        .await;
}

#[when("the first decision of the last search is read by id over GraphQL")]
async fn first_decision_over_graphql(world: &mut AppWorld) {
    let id = world
        .reply()
        .json()
        .pointer("/data/accessDecisions/items/0/id")
        .and_then(serde_json::Value::as_str)
        .expect("the search returned a decision")
        .to_owned();
    let query = format!("{{ accessDecision(id: \"{id}\") {{ {FIELDS} }} }}");
    let body = json!({ "query": query }).to_string();
    world
        .send("POST", "/api/graphql", Some("application/json"), &body)
        .await;
}
