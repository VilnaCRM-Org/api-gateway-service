use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessDecision, AccessEntry, AccessLane, AccessLogCursor, AccessLogFilter, AccessLogQuery as _,
    AccessLogQueryError, AccessLogRange, AccessLogSearch, AccessRecord, DecisionReason,
    SubjectKind,
};
use serde_json::json;
use shared_domain::Uuid;

use super::{LokiAccessLogQuery, LokiQueryTransport, LokiResponse};
use crate::access_log::stdout_sink::render_entry;

/// A transport that answers the requests in order and keeps their URLs.
#[derive(Debug)]
struct ScriptedTransport {
    answers: Mutex<Vec<Result<LokiResponse, AccessLogQueryError>>>,
    urls: Mutex<Vec<String>>,
}

impl ScriptedTransport {
    fn answering(mut answers: Vec<Result<LokiResponse, AccessLogQueryError>>) -> Arc<Self> {
        answers.reverse();
        Arc::new(Self {
            answers: Mutex::new(answers),
            urls: Mutex::new(Vec::new()),
        })
    }

    fn urls(&self) -> Vec<String> {
        self.urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl LokiQueryTransport for ScriptedTransport {
    async fn get(&self, url: &str) -> Result<LokiResponse, AccessLogQueryError> {
        self.urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(url.to_owned());
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or(Err(AccessLogQueryError::Unavailable))
    }
}

fn adapter(transport: &Arc<ScriptedTransport>) -> LokiAccessLogQuery {
    let transport: Arc<dyn LokiQueryTransport> = Arc::<ScriptedTransport>::clone(transport);
    LokiAccessLogQuery::new(transport, "http://loki:3100", "iam-gateway", "test")
}

fn id(n: u64) -> Uuid {
    Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{n:012x}")).unwrap()
}

fn record(n: u64) -> AccessRecord {
    AccessRecord {
        decision_id: id(n),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_000_000))
            .unwrap(),
        method: "GET".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: None,
        route_template: None,
        status: 403,
        upstream: Some("user-service".to_owned()),
        latency_us: 10,
        bytes_in: 0,
        bytes_out: 0,
        request_id: None,
        subject_id: Some("user-1".to_owned()),
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

/// The answer of Loki with one stream of the entries `(n, nanos)` in the order given.
fn answer_of(entries: &[(u64, u64)]) -> LokiResponse {
    let values: Vec<_> = entries
        .iter()
        .map(|(n, nanos)| {
            let line = render_entry(
                AccessLane::Audit,
                &AccessEntry::Record(Box::new(record(*n))),
            );
            json!([nanos.to_string(), line])
        })
        .collect();
    let body = json!({
        "status": "success",
        "data": { "resultType": "streams", "result": [{ "stream": {}, "values": values }] },
    });
    LokiResponse {
        status: 200,
        body: body.to_string().into_bytes(),
    }
}

fn status(status: u16) -> LokiResponse {
    LokiResponse {
        status,
        body: b"nope".to_vec(),
    }
}

fn range() -> AccessLogRange {
    let at = |seconds| {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap()
    };
    AccessLogRange::new(at(0), at(1_000), Duration::from_hours(1)).unwrap()
}

fn search(cursor: Option<AccessLogCursor>, limit: u32) -> AccessLogSearch {
    AccessLogSearch {
        range: range(),
        filter: AccessLogFilter::default(),
        cursor,
        limit,
    }
}

#[tokio::test]
async fn a_search_asks_for_the_range_the_limit_and_the_fixed_labels() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[(1, 900)]))]);

    let found = adapter(&transport).search(&search(None, 3)).await.unwrap();

    assert_eq!(found.len(), 1);
    let urls = transport.urls();
    assert_eq!(urls.len(), 1);
    assert!(urls[0].starts_with("http://loki:3100/loki/api/v1/query_range?query="));
    assert!(urls[0].contains("app%3D%22iam-gateway%22"));
    assert!(urls[0].contains("start=0&end=1000000000000&limit=3&direction=backward"));
}

#[tokio::test]
async fn a_search_returns_no_more_entries_than_its_limit() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[(3, 30), (2, 20), (1, 10)]))]);

    let found = adapter(&transport).search(&search(None, 2)).await.unwrap();

    let nanos: Vec<u64> = found.iter().map(|entry| entry.timestamp_nanos).collect();
    assert_eq!(nanos, [30, 20]);
}

#[tokio::test]
async fn a_cursor_ends_the_range_after_its_timestamp_and_skips_the_entries_already_returned() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[
        (5, 40),
        (4, 40),
        (3, 40),
        (2, 30),
        (1, 20),
    ]))]);
    let cursor = AccessLogCursor {
        timestamp_nanos: 40,
        returned: 2,
    };

    let found = adapter(&transport)
        .search(&search(Some(cursor), 2))
        .await
        .unwrap();

    let urls = transport.urls();
    assert!(urls[0].contains("end=41&limit=4&"));
    let ids: Vec<Uuid> = found.iter().map(|entry| entry.record.decision_id).collect();
    assert_eq!(ids, [id(3), id(2)]);
}

#[tokio::test]
async fn a_cursor_in_a_range_that_ends_earlier_keeps_the_end_of_the_range() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[]))]);
    let cursor = AccessLogCursor {
        timestamp_nanos: u64::MAX,
        returned: 0,
    };

    adapter(&transport)
        .search(&search(Some(cursor), 5))
        .await
        .unwrap();

    assert!(transport.urls()[0].contains("end=1000000000000&"));
}

#[tokio::test]
async fn a_decision_is_looked_up_in_the_window_around_its_timestamp() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[(7, 55)]))]);

    let found = adapter(&transport).find(id(7)).await.unwrap();

    assert_eq!(found.map(|entry| entry.record.decision_id), Some(id(7)));
    let url = &transport.urls()[0];
    assert!(url.contains("decision_id%3D%220190f2a8-7b3c-7d4e-8f10-000000000007%22"));
    assert!(url.contains("limit=1&"));
}

#[tokio::test]
async fn a_decision_that_the_window_does_not_hold_is_none() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[]))]);

    assert_eq!(adapter(&transport).find(id(7)).await.unwrap(), None);
}

#[tokio::test]
async fn an_entry_of_another_decision_is_not_the_decision_that_was_asked_for() {
    let transport = ScriptedTransport::answering(vec![Ok(answer_of(&[(8, 55)]))]);

    assert_eq!(adapter(&transport).find(id(7)).await.unwrap(), None);
}

#[tokio::test]
async fn an_id_that_is_not_a_uuid_v7_is_none_without_a_query() {
    let transport = ScriptedTransport::answering(Vec::new());
    let v4 = Uuid::parse("5f1c2d3e-4b5a-4c6d-8e7f-0123456789ab").unwrap();

    assert_eq!(adapter(&transport).find(v4).await.unwrap(), None);
    assert_eq!(transport.urls().len(), 0);
}

#[tokio::test]
async fn a_transport_that_times_out_or_cannot_connect_fails_the_search() {
    for failure in [
        AccessLogQueryError::Timeout,
        AccessLogQueryError::Unavailable,
    ] {
        let transport = ScriptedTransport::answering(vec![Err(failure)]);

        let error = adapter(&transport)
            .search(&search(None, 3))
            .await
            .unwrap_err();

        assert_eq!(error, failure);
    }
}

#[tokio::test]
async fn a_gateway_timeout_of_loki_is_a_timeout_and_any_other_failure_is_unavailable() {
    for (answered, expected) in [
        (504, AccessLogQueryError::Timeout),
        (500, AccessLogQueryError::Unavailable),
        (429, AccessLogQueryError::Unavailable),
        (400, AccessLogQueryError::Unavailable),
    ] {
        let transport = ScriptedTransport::answering(vec![Ok(status(answered))]);

        let error = adapter(&transport)
            .search(&search(None, 3))
            .await
            .unwrap_err();

        assert_eq!(error, expected, "{answered}");
    }
}

#[tokio::test]
async fn an_answer_that_cannot_be_read_fails_the_search_without_a_partial_page() {
    let transport = ScriptedTransport::answering(vec![Ok(LokiResponse {
        status: 200,
        body: b"{\"status\":\"success\",\"data\":{\"result\":[{\"values\":[[\"1\",\"junk\"]]}]}}"
            .to_vec(),
    })]);

    let error = adapter(&transport)
        .search(&search(None, 3))
        .await
        .unwrap_err();

    assert_eq!(error, AccessLogQueryError::Unavailable);
}

#[tokio::test]
async fn loki_is_ready_when_its_ready_endpoint_answers_with_a_success_status() {
    let transport = ScriptedTransport::answering(vec![Ok(status(200)), Ok(status(503))]);
    let adapter = adapter(&transport);

    assert_eq!(adapter.ready().await, Ok(()));
    assert_eq!(adapter.ready().await, Err(AccessLogQueryError::Unavailable));
    assert_eq!(
        transport.urls(),
        ["http://loki:3100/ready", "http://loki:3100/ready"]
    );
}
