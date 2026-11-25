use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessDecision, AccessLogCursor, AccessLogEntry, AccessLogFilter, AccessLogQuery,
    AccessLogQueryError, DecisionReason, SecurityAuditLog, SubjectKind,
};
use rstest::rstest;
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{
    AUDIT_ACTION, AccessDecisionPage, GetAccessDecisionsQuery, GetAccessDecisionsQueryHandler,
    MAX_PAGE_SIZE, SEARCH_TARGET_ID, TARGET_TYPE,
};
use crate::access_decision_fixtures::{FakeAccessLogQuery, decision_id, entry};
use crate::error::IamError;
use crate::security_audit_fixtures::{actor, at};

const DAY: Duration = Duration::from_hours(24);

fn instant(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn handler_over(
    store: &Arc<FakeAccessLogQuery>,
    log: &Arc<FakeSecurityAuditLog>,
) -> GetAccessDecisionsQueryHandler {
    let store: Arc<dyn AccessLogQuery> = Arc::<FakeAccessLogQuery>::clone(store);
    let log: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    GetAccessDecisionsQueryHandler::new(
        store,
        log,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(SequenceUuidGenerator::starting_at(1_000)),
        DAY,
    )
}

fn query(limit: u32) -> GetAccessDecisionsQuery {
    GetAccessDecisionsQuery {
        actor: actor(),
        from: instant(0),
        until: instant(3_600),
        filter: AccessLogFilter::default(),
        limit,
        cursor: None,
    }
}

/// `count` entries, one per second from the second `1`, the decision `n` at second `n`.
fn entries(count: u64) -> Vec<AccessLogEntry> {
    (1..=count)
        .map(|n| entry(n, n.checked_mul(1_000_000_000).unwrap()))
        .collect()
}

fn ids(page: &AccessDecisionPage) -> Vec<u64> {
    page.entries
        .iter()
        .map(|entry| entry.timestamp_nanos / 1_000_000_000)
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetAccessDecisionsQuery::NAME, "GetAccessDecisionsQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_its_last_decision_as_the_cursor() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(5)));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let page = handler_over(&store, &log).handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [5, 4]);
    assert_eq!(
        page.next,
        Some(AccessLogCursor {
            timestamp_nanos: 4_000_000_000,
            returned: 1,
        })
    );
}

#[tokio::test]
async fn the_last_page_has_no_cursor() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(2)));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let page = handler_over(&store, &log).handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [2, 1]);
    assert_eq!(page.next, None);
}

#[tokio::test]
async fn following_the_cursors_visits_every_decision_exactly_once_including_shared_timestamps() {
    let mut stock = entries(4);
    stock.extend((10..14).map(|n| entry(n, 2_000_000_000)));
    let total = stock.len();
    let store = Arc::new(FakeAccessLogQuery::holding(stock));
    let log = Arc::new(FakeSecurityAuditLog::new());
    let handler = handler_over(&store, &log);
    let mut seen = Vec::new();
    let mut cursor = None;

    loop {
        let page = handler
            .handle(GetAccessDecisionsQuery { cursor, ..query(3) })
            .await
            .unwrap();
        seen.extend(page.entries.iter().map(|found| found.record.decision_id));
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(seen.len(), total);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), total);
}

#[tokio::test]
async fn the_store_is_asked_for_one_decision_more_than_the_page_and_the_range_of_the_query() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(1)));
    let log = Arc::new(FakeSecurityAuditLog::new());

    handler_over(&store, &log).handle(query(7)).await.unwrap();

    let searches = store.searches();
    assert_eq!(searches.len(), 1);
    assert_eq!(searches[0].limit, 8);
    assert_eq!(searches[0].range.start_nanos(), 0);
    assert_eq!(searches[0].range.until_nanos(), 3_600_000_000_000);
}

#[rstest]
#[case::zero(0, 2)]
#[case::above_the_maximum(MAX_PAGE_SIZE + 100, MAX_PAGE_SIZE + 1)]
#[tokio::test]
async fn a_page_size_outside_the_bounds_is_brought_into_them(
    #[case] requested: u32,
    #[case] asked_of_the_store: u32,
) {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(1)));
    let log = Arc::new(FakeSecurityAuditLog::new());

    handler_over(&store, &log)
        .handle(query(requested))
        .await
        .unwrap();

    assert_eq!(store.searches()[0].limit, asked_of_the_store);
}

#[rstest]
#[case::longer_than_the_maximum(instant(0), instant(86_401), "until")]
#[case::inverted(instant(10), instant(5), "until")]
#[tokio::test]
async fn a_range_that_cannot_be_queried_is_a_violation_and_reaches_neither_store_nor_log(
    #[case] from: SystemTime,
    #[case] until: SystemTime,
    #[case] property: &str,
) {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(1)));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let error = handler_over(&store, &log)
        .handle(GetAccessDecisionsQuery {
            from,
            until,
            ..query(5)
        })
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("expected a violation");
    };
    assert_eq!(violations[0].property_path, property);
    assert_eq!(store.searches().len(), 0);
    assert_eq!(log.recorded().len(), 0);
}

#[tokio::test]
async fn a_search_is_recorded_in_the_audit_log_with_its_conditions() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(3)));
    let log = Arc::new(FakeSecurityAuditLog::new());
    let filtered = GetAccessDecisionsQuery {
        filter: AccessLogFilter {
            decision: Some(AccessDecision::Deny),
            status: Some(403),
            upstream: Some("user-service".to_owned()),
            ..AccessLogFilter::default()
        },
        ..query(2)
    };

    handler_over(&store, &log).handle(filtered).await.unwrap();

    let recorded = log.recorded();
    assert_eq!(recorded.len(), 1);
    let parts = recorded[0].event().parts();
    assert_eq!(parts.actor, actor());
    assert_eq!(parts.action.as_str(), AUDIT_ACTION);
    assert_eq!(parts.target.target_type(), TARGET_TYPE);
    assert_eq!(parts.target.target_id(), SEARCH_TARGET_ID);
    assert_eq!(
        parts
            .after
            .as_ref()
            .map(|summary| summary.as_str().to_owned()),
        Some("limit=2;from=0;until=3600;decision=deny;upstream=user-service;status=403".to_owned())
    );
}

#[tokio::test]
async fn a_search_with_every_condition_records_every_condition() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(3)));
    let log = Arc::new(FakeSecurityAuditLog::new());
    let cursor = AccessLogCursor {
        timestamp_nanos: 3_000_000_000,
        returned: 1,
    };
    let route = decision_id(9);
    let filtered = GetAccessDecisionsQuery {
        cursor: Some(cursor),
        filter: AccessLogFilter {
            subject_id: Some("alice".to_owned()),
            subject_kind: Some(SubjectKind::User),
            decision: Some(AccessDecision::Deny),
            reason: Some(DecisionReason::PermissionMissing),
            upstream: Some("user-service".to_owned()),
            route_id: Some(route),
            status: Some(403),
        },
        ..query(2)
    };

    handler_over(&store, &log).handle(filtered).await.unwrap();

    let recorded = log.recorded();
    let parts = recorded[0].event().parts();
    assert_eq!(
        parts
            .after
            .as_ref()
            .map(|summary| summary.as_str().to_owned()),
        Some(format!(
            "limit=2;cursor={};from=0;until=3600;subject_id=alice;subject_kind={};decision=deny;reason={};upstream=user-service;route_id={route};status=403",
            cursor.encode(),
            SubjectKind::User.as_str(),
            DecisionReason::PermissionMissing,
        ))
    );
}

#[tokio::test]
async fn a_search_that_names_a_token_is_recorded_without_its_conditions() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(3)));
    let log = Arc::new(FakeSecurityAuditLog::new());
    let filtered = GetAccessDecisionsQuery {
        filter: AccessLogFilter {
            subject_id: Some("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl".to_owned()),
            ..AccessLogFilter::default()
        },
        ..query(2)
    };

    handler_over(&store, &log).handle(filtered).await.unwrap();

    let recorded = log.recorded();
    let parts = recorded[0].event().parts();
    assert_eq!(
        parts
            .after
            .as_ref()
            .map(|summary| summary.as_str().to_owned()),
        Some("filter=unsummarised".to_owned())
    );
}

#[rstest]
#[case::timeout(AccessLogQueryError::Timeout)]
#[case::unavailable(AccessLogQueryError::Unavailable)]
#[tokio::test]
async fn a_store_that_fails_returns_no_page_and_leaves_no_audit_record(
    #[case] failure: AccessLogQueryError,
) {
    let store = Arc::new(FakeAccessLogQuery::failing(failure));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let error = handler_over(&store, &log)
        .handle(query(5))
        .await
        .unwrap_err();

    match failure {
        AccessLogQueryError::Timeout => assert!(matches!(error, IamError::AccessLogTimeout)),
        AccessLogQueryError::Unavailable => {
            assert!(matches!(error, IamError::AccessLogUnavailable));
        }
    }
    assert_eq!(log.recorded().len(), 0);
}

#[tokio::test]
async fn a_search_that_cannot_be_audited_is_not_served() {
    let store = Arc::new(FakeAccessLogQuery::holding(entries(3)));
    let log = Arc::new(FakeSecurityAuditLog::failing());

    let error = handler_over(&store, &log)
        .handle(query(2))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn an_empty_range_of_the_store_is_an_empty_page_that_is_still_audited() {
    let store = Arc::new(FakeAccessLogQuery::holding(Vec::new()));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let page = handler_over(&store, &log).handle(query(5)).await.unwrap();

    assert_eq!(page.entries.len(), 0);
    assert_eq!(page.next, None);
    assert_eq!(log.recorded().len(), 1);
}
