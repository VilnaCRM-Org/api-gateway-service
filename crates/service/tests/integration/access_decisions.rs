//! The queries of the access decisions (Story 14.3, FR-51, FR-54, NFR-44) in process: the
//! production adapter and use case against the compose Loki, and against local HTTP stubs of Loki
//! that answer slower than the query timeout or refuse the connection.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use health_check_domain::{Dependency, HealthProbe as _};
use iam_application::{
    AccessDecisionPage, GetAccessDecisionsQuery, GetAccessDecisionsQueryHandler, IamError,
};
use iam_domain::{
    AccessDecision, AccessEntry, AccessLane, AccessLogCursor, AccessLogFilter, AccessLogQuery,
    AccessLogSink as _, AccessRecord, ActorRef, DecisionReason, SecurityAuditLog, SubjectKind,
    SystemComponent,
};
use iam_infrastructure::{
    LokiAccessLogQuery, LokiPushAccessLogSink, LokiQueryTransport, LokiSinkSettings,
};
use service::bootstrap::gateway::access_log::LOKI_APP_LABEL;
use service::bootstrap::gateway::access_log::loki_transport::HyperLokiTransport;
use service::bootstrap::{AccessLogStoreProbe, HyperLokiQueryTransport};
use shared_domain::{Clock as _, QueryHandler as _, UuidGenerator as _};
use shared_infrastructure::clock::SystemClock;
use shared_infrastructure::id::UuidV7Generator;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;
use tokio::net::TcpListener;

use crate::support::stack_variable;

/// The longest range these tests query.
const MAX_RANGE: Duration = Duration::from_hours(2);

/// The timeout of a query against a stub.
const STUB_TIMEOUT: Duration = Duration::from_millis(300);

/// The timeout of a query against the compose Loki.
const LOKI_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the pushed decisions may take to become visible.
const VISIBLE_WITHIN: Duration = Duration::from_secs(60);

/// The p95 target of NFR-44 for a one-hour range at first-release volume.
const NFR_44_ONE_HOUR: Duration = Duration::from_secs(5);

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its stub of Loki on a free loopback port"
)]
async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// The handler over a store that reads `base`, with a transport whose calls take at most
/// `timeout`.
fn handler_over(base: &str, timeout: Duration) -> GetAccessDecisionsQueryHandler {
    let transport: Arc<dyn LokiQueryTransport> =
        Arc::new(HyperLokiQueryTransport::new("iam", timeout).unwrap());
    let store: Arc<dyn AccessLogQuery> = Arc::new(LokiAccessLogQuery::new(
        transport,
        base,
        LOKI_APP_LABEL,
        "test",
    ));
    let log: Arc<dyn SecurityAuditLog> = Arc::new(FakeSecurityAuditLog::new());
    GetAccessDecisionsQueryHandler::new(
        store,
        log,
        Arc::new(SystemClock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        MAX_RANGE,
    )
}

fn query(subject: &str, cursor: Option<AccessLogCursor>, limit: u32) -> GetAccessDecisionsQuery {
    let now = SystemClock.now();
    GetAccessDecisionsQuery {
        actor: ActorRef::System(SystemComponent::Startup),
        from: now.checked_sub(Duration::from_hours(1)).unwrap(),
        until: now.checked_add(Duration::from_hours(1)).unwrap(),
        filter: AccessLogFilter {
            subject_id: Some(subject.to_owned()),
            ..AccessLogFilter::default()
        },
        limit,
        cursor,
    }
}

fn record(subject: &str, occurred_at: SystemTime) -> AccessRecord {
    AccessRecord {
        decision_id: UuidV7Generator.generate(),
        occurred_at,
        method: "GET".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: None,
        route_template: Some("/api/users/{id}".to_owned()),
        status: 403,
        upstream: Some("user-service".to_owned()),
        latency_us: 10,
        bytes_in: 0,
        bytes_out: 0,
        request_id: None,
        subject_id: Some(subject.to_owned()),
        subject_kind: Some(SubjectKind::User),
        decision: AccessDecision::Deny,
        reason: DecisionReason::PermissionMissing,
        permission_key: None,
        denied: Vec::new(),
        project_id: None,
        policy_version: None,
        credential_digest_prefix: None,
    }
}

/// Pushes `records` to the compose Loki as the audit lane of a gateway does.
async fn push(records: Vec<AccessRecord>) {
    let push_url = stack_variable("LOKI_PUSH_URL").parse().unwrap();
    tokio::task::spawn_blocking(move || {
        let sink = LokiPushAccessLogSink::start(
            LokiSinkSettings {
                app: LOKI_APP_LABEL.to_owned(),
                env: "test".to_owned(),
                flush_interval: Duration::from_millis(100),
            },
            Arc::new(HyperLokiTransport::new(push_url, "iam").unwrap()),
        )
        .unwrap();
        for record in records {
            sink.write(AccessLane::Audit, &AccessEntry::Record(Box::new(record)));
        }
        sink.flush();
    })
    .await
    .unwrap();
}

/// Every page of the decisions of `subject`, newest first, `limit` entries at most each.
async fn pages(
    handler: &GetAccessDecisionsQueryHandler,
    subject: &str,
    limit: u32,
) -> Vec<AccessDecisionPage> {
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let page = handler.handle(query(subject, cursor, limit)).await.unwrap();
        cursor = page.next;
        pages.push(page);
        if cursor.is_none() {
            return pages;
        }
    }
}

fn unique(prefix: &str) -> String {
    let nanos = SystemClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

#[tokio::test]
async fn pages_of_at_most_500_return_each_of_1200_decisions_once_including_shared_timestamps() {
    let subject = unique("paging-it");
    let base = SystemClock
        .now()
        .checked_sub(Duration::from_mins(10))
        .unwrap();
    // Every two decisions share a timestamp, so a page boundary can fall between them.
    let records: Vec<AccessRecord> = (0..1_200_u64)
        .map(|index| {
            let at = base.checked_add(Duration::from_micros(index / 2)).unwrap();
            record(&subject, at)
        })
        .collect();
    let pushed: BTreeSet<_> = records.iter().map(|record| record.decision_id).collect();
    push(records).await;
    let handler = handler_over(&stack_variable("LOKI_QUERY_URL"), LOKI_TIMEOUT);

    let deadline = tokio::time::Instant::now() + VISIBLE_WITHIN;
    let found = loop {
        let found = pages(&handler, &subject, 500).await;
        let total: usize = found.iter().map(|page| page.entries.len()).sum();
        if total >= pushed.len() || tokio::time::Instant::now() >= deadline {
            break found;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let sizes: Vec<usize> = found.iter().map(|page| page.entries.len()).collect();
    assert_eq!(sizes, [500, 500, 200]);
    let entries: Vec<_> = found.iter().flat_map(|page| &page.entries).collect();
    let returned: BTreeSet<_> = entries
        .iter()
        .map(|entry| entry.record.decision_id)
        .collect();
    assert_eq!(returned, pushed);
    assert!(
        entries
            .windows(2)
            .all(|pair| pair[0].timestamp_nanos >= pair[1].timestamp_nanos)
    );
}

#[tokio::test]
async fn a_one_hour_query_of_the_compose_loki_is_timed_against_the_nfr_44_target() {
    let subject = unique("timing-it");
    push(vec![record(&subject, SystemClock.now())]).await;
    let handler = handler_over(&stack_variable("LOKI_QUERY_URL"), LOKI_TIMEOUT);
    let deadline = tokio::time::Instant::now() + VISIBLE_WITHIN;
    while pages(&handler, &subject, 500)
        .await
        .iter()
        .all(|page| page.entries.is_empty())
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the decision never became visible"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let started = tokio::time::Instant::now();
    let page = handler.handle(query(&subject, None, 500)).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(page.entries.len(), 1);
    // A measurement of the compose host, not a gate: the target is a p95 at first-release volume.
    eprintln!(
        "NFR-44 one-hour range: {elapsed:?} on the compose Loki (target: p95 at most {NFR_44_ONE_HOUR:?})"
    );
}

async fn slow_response() -> StatusCode {
    tokio::time::sleep(Duration::from_secs(10)).await;
    StatusCode::OK
}

#[tokio::test]
async fn a_query_slower_than_the_timeout_is_a_timeout_and_returns_no_page() {
    let app = Router::new().route("/loki/api/v1/query_range", get(slow_response));
    let listener = bind().await;
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let handler = handler_over(&base, STUB_TIMEOUT);

    let error = handler.handle(query("anyone", None, 10)).await.unwrap_err();

    assert!(matches!(error, IamError::AccessLogTimeout));
}

#[tokio::test]
async fn a_loki_that_refuses_the_connection_is_unavailable() {
    let listener = bind().await;
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let handler = handler_over(&base, STUB_TIMEOUT);

    let error = handler.handle(query("anyone", None, 10)).await.unwrap_err();

    assert!(matches!(error, IamError::AccessLogUnavailable));
}

#[tokio::test]
async fn the_access_log_store_is_healthy_while_loki_is_ready_and_unhealthy_when_it_is_not() {
    let healthy = access_log_probe(&stack_variable("LOKI_QUERY_URL"));
    let listener = bind().await;
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let unhealthy = access_log_probe(&dead);

    assert_eq!(healthy.dependency(), Dependency::AccessLogStore);
    assert!(healthy.check().await.is_ok());
    assert!(unhealthy.check().await.is_err());
}

fn access_log_probe(base: &str) -> AccessLogStoreProbe {
    let transport: Arc<dyn LokiQueryTransport> =
        Arc::new(HyperLokiQueryTransport::new("iam", Duration::from_secs(3)).unwrap());
    AccessLogStoreProbe::new(Arc::new(LokiAccessLogQuery::new(
        transport,
        base,
        LOKI_APP_LABEL,
        "test",
    )))
}
