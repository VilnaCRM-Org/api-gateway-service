use std::sync::Arc;

use iam_domain::{AuditOutcome, SecurityAuditFilter, SecurityAuditLog, StoredSecurityAuditEvent};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{
    AUDIT_ACTION, GetSecurityAuditEventsQuery, GetSecurityAuditEventsQueryHandler, MAX_PAGE_SIZE,
    SecurityAuditEventPage,
};
use crate::error::IamError;
use crate::security_audit_fixtures::{actor, at, record};

/// The log that holds `count` committed records and a handler over it.
async fn handler(
    count: u8,
) -> (
    GetSecurityAuditEventsQueryHandler,
    Arc<FakeSecurityAuditLog>,
) {
    let log = Arc::new(FakeSecurityAuditLog::new());
    for seq in 1..=count {
        let record = record(seq, AuditOutcome::Committed);
        log.append_batch(std::slice::from_ref(record.event()))
            .await
            .unwrap();
    }
    (handler_over(&log), log)
}

fn handler_over(log: &Arc<FakeSecurityAuditLog>) -> GetSecurityAuditEventsQueryHandler {
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    GetSecurityAuditEventsQueryHandler::new(
        port,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(SequenceUuidGenerator::starting_at(1_000)),
    )
}

fn query(limit: u32) -> GetSecurityAuditEventsQuery {
    GetSecurityAuditEventsQuery {
        actor: actor(),
        filter: SecurityAuditFilter::new(),
        limit,
        before_seq: None,
    }
}

fn seqs(page: &SecurityAuditEventPage) -> Vec<i64> {
    page.events
        .iter()
        .map(StoredSecurityAuditEvent::seq)
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetSecurityAuditEventsQuery::NAME,
        "GetSecurityAuditEventsQuery"
    );
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_its_last_record_as_the_cursor() {
    let (handler, _log) = handler(5).await;

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(seqs(&page), [5, 4]);
    assert_eq!(page.next_before, Some(4));
}

#[tokio::test]
async fn following_the_cursors_visits_every_record_exactly_once() {
    let (handler, _log) = handler(5).await;
    let mut seen = Vec::new();
    let mut before = None;

    loop {
        let page = handler
            .handle(GetSecurityAuditEventsQuery {
                before_seq: before,
                ..query(2)
            })
            .await
            .unwrap();
        seen.extend(seqs(&page).into_iter().filter(|seq| *seq <= 5));
        before = page.next_before;
        if before.is_none() {
            break;
        }
    }

    assert_eq!(seen, [5, 4, 3, 2, 1]);
}

#[tokio::test]
async fn a_page_that_holds_the_rest_has_no_cursor() {
    let (handler, _log) = handler(2).await;

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(seqs(&page), [2, 1]);
    assert_eq!(page.next_before, None);
}

#[tokio::test]
async fn the_filter_keeps_only_the_records_that_meet_it() {
    let (handler, log) = handler(2).await;
    let rejected = record(3, AuditOutcome::Rejected);
    log.append_batch(std::slice::from_ref(rejected.event()))
        .await
        .unwrap();

    let page = handler
        .handle(GetSecurityAuditEventsQuery {
            filter: SecurityAuditFilter::new().with_outcome(AuditOutcome::Rejected),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(seqs(&page), [3]);
}

#[tokio::test]
async fn a_limit_outside_the_range_is_brought_into_it() {
    let (handler, _log) = handler(3).await;

    let none = handler.handle(query(0)).await.unwrap();
    let many = handler.handle(query(MAX_PAGE_SIZE + 50)).await.unwrap();

    assert_eq!(none.events.len(), 1);
    assert_eq!(many.events.len(), 4);
}

#[tokio::test]
async fn a_search_is_recorded_after_the_page_is_read_and_is_not_in_that_page() {
    let (handler, log) = handler(2).await;

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(seqs(&page), [2, 1]);
    let recorded = log.recorded();
    assert_eq!(recorded.len(), 3);
    let parts = recorded[2].event().parts();
    assert_eq!(parts.actor, actor());
    assert_eq!(parts.action.as_str(), AUDIT_ACTION);
    assert_eq!(parts.target.target_type(), "security_audit_event");
    assert_eq!(parts.target.target_id(), "query");
    assert_eq!(parts.outcome, AuditOutcome::Committed);
    assert_eq!(parts.occurred_at, at(900));
    assert_eq!(parts.after.as_ref().unwrap().as_str(), "limit=10");
}

#[tokio::test]
async fn a_log_that_cannot_be_read_is_the_error_of_the_query() {
    let handler = handler_over(&Arc::new(FakeSecurityAuditLog::failing()));

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
