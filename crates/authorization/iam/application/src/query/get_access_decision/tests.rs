use std::sync::Arc;

use iam_domain::{AccessLogQuery, AccessLogQueryError, SecurityAuditLog};
use rstest::rstest;
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{AUDIT_ACTION, GetAccessDecisionQuery, GetAccessDecisionQueryHandler};
use crate::access_decision_fixtures::{FakeAccessLogQuery, decision_id, entry};
use crate::error::IamError;
use crate::query::get_access_decisions::TARGET_TYPE;
use crate::security_audit_fixtures::{actor, at};

fn handler_over(
    store: &Arc<FakeAccessLogQuery>,
    log: &Arc<FakeSecurityAuditLog>,
) -> GetAccessDecisionQueryHandler {
    let store: Arc<dyn AccessLogQuery> = Arc::<FakeAccessLogQuery>::clone(store);
    let log: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    GetAccessDecisionQueryHandler::new(
        store,
        log,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(SequenceUuidGenerator::starting_at(1_000)),
    )
}

fn query(n: u64) -> GetAccessDecisionQuery {
    GetAccessDecisionQuery {
        actor: actor(),
        id: decision_id(n),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetAccessDecisionQuery::NAME, "GetAccessDecisionQuery");
}

#[tokio::test]
async fn a_decision_that_is_found_is_returned_and_the_read_is_audited() {
    let store = Arc::new(FakeAccessLogQuery::holding(vec![entry(1, 5_000_000_000)]));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let found = handler_over(&store, &log).handle(query(1)).await.unwrap();

    assert_eq!(found, Some(entry(1, 5_000_000_000)));
    let recorded = log.recorded();
    assert_eq!(recorded.len(), 1);
    let parts = recorded[0].event().parts();
    assert_eq!(parts.action.as_str(), AUDIT_ACTION);
    assert_eq!(parts.target.target_type(), TARGET_TYPE);
    assert_eq!(parts.target.target_id(), decision_id(1).to_string());
    assert_eq!(
        parts
            .after
            .as_ref()
            .map(|summary| summary.as_str().to_owned()),
        Some("timestamp_ns=5000000000".to_owned())
    );
}

#[tokio::test]
async fn an_unknown_decision_is_none_and_is_not_audited() {
    let store = Arc::new(FakeAccessLogQuery::holding(vec![entry(1, 5_000_000_000)]));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let found = handler_over(&store, &log).handle(query(2)).await.unwrap();

    assert_eq!(found, None);
    assert_eq!(log.recorded().len(), 0);
}

#[rstest]
#[case::timeout(AccessLogQueryError::Timeout)]
#[case::unavailable(AccessLogQueryError::Unavailable)]
#[tokio::test]
async fn a_store_that_fails_fails_the_read(#[case] failure: AccessLogQueryError) {
    let store = Arc::new(FakeAccessLogQuery::failing(failure));
    let log = Arc::new(FakeSecurityAuditLog::new());

    let error = handler_over(&store, &log)
        .handle(query(1))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        IamError::AccessLogTimeout | IamError::AccessLogUnavailable
    ));
    assert_eq!(log.recorded().len(), 0);
}

#[tokio::test]
async fn a_read_that_cannot_be_audited_is_not_served() {
    let store = Arc::new(FakeAccessLogQuery::holding(vec![entry(1, 5_000_000_000)]));
    let log = Arc::new(FakeSecurityAuditLog::failing());

    let error = handler_over(&store, &log)
        .handle(query(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
