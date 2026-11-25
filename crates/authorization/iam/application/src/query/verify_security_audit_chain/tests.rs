use std::sync::Arc;

use iam_domain::{
    AuditChainHead, AuditOutcome, ChainBreak, ChainBreakCause, ChainVerification, SecurityAuditLog,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{AUDIT_ACTION, VerifySecurityAuditChainQuery, VerifySecurityAuditChainQueryHandler};
use crate::error::IamError;
use crate::security_audit_fixtures::{actor, at, record};

async fn log_with(count: u8) -> Arc<FakeSecurityAuditLog> {
    let log = Arc::new(FakeSecurityAuditLog::new());
    for seq in 1..=count {
        let record = record(seq, AuditOutcome::Committed);
        log.append_batch(std::slice::from_ref(record.event()))
            .await
            .unwrap();
    }
    log
}

fn handler_over(log: &Arc<FakeSecurityAuditLog>) -> VerifySecurityAuditChainQueryHandler {
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    VerifySecurityAuditChainQueryHandler::new(
        port,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(SequenceUuidGenerator::starting_at(1_000)),
    )
}

fn query(anchors: Vec<AuditChainHead>) -> VerifySecurityAuditChainQuery {
    VerifySecurityAuditChainQuery {
        actor: actor(),
        anchors,
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        VerifySecurityAuditChainQuery::NAME,
        "VerifySecurityAuditChainQuery"
    );
}

#[tokio::test]
async fn an_intact_chain_is_valid_with_the_number_of_records_checked() {
    let log = log_with(3).await;

    let verification = handler_over(&log).handle(query(Vec::new())).await.unwrap();

    assert_eq!(verification, ChainVerification::valid(3));
}

#[tokio::test]
async fn a_matching_anchor_keeps_the_chain_valid() {
    let log = log_with(3).await;
    let stored = log.recorded();
    let anchor = AuditChainHead::new(2, stored[1].hash()).unwrap();

    let verification = handler_over(&log)
        .handle(query(vec![anchor]))
        .await
        .unwrap();

    assert!(verification.is_valid());
}

#[tokio::test]
async fn an_anchor_with_another_hash_is_invalid_at_the_anchored_record() {
    let log = log_with(3).await;
    let stored = log.recorded();
    let anchor = AuditChainHead::new(2, stored[2].hash()).unwrap();

    let verification = handler_over(&log)
        .handle(query(vec![anchor]))
        .await
        .unwrap();

    let id = stored[1].event().parts().id;
    assert_eq!(
        verification,
        ChainVerification::invalid(2, ChainBreak::new(2, Some(id), ChainBreakCause::Anchor))
    );
}

#[tokio::test]
async fn the_verification_is_recorded_in_the_log_under_the_asking_actor() {
    let log = log_with(2).await;

    handler_over(&log).handle(query(Vec::new())).await.unwrap();

    let stored = log.recorded();
    assert_eq!(stored.len(), 3);
    let parts = stored[2].event().parts();
    assert_eq!(parts.actor, actor());
    assert_eq!(parts.action.as_str(), AUDIT_ACTION);
    assert_eq!(parts.target.target_type(), "security_audit_event");
    assert_eq!(parts.target.target_id(), "chain");
    assert_eq!(
        parts.after.as_ref().map(iam_domain::AuditSummary::as_str),
        Some("anchors=0;checked=2;result=valid")
    );
}

#[tokio::test]
async fn an_invalid_verdict_is_recorded_with_its_place_and_cause() {
    let log = log_with(3).await;
    let stored = log.recorded();
    let anchor = AuditChainHead::new(2, stored[2].hash()).unwrap();

    handler_over(&log)
        .handle(query(vec![anchor]))
        .await
        .unwrap();

    let stored = log.recorded();
    assert_eq!(
        stored[3]
            .event()
            .parts()
            .after
            .as_ref()
            .map(iam_domain::AuditSummary::as_str),
        Some("anchors=1;checked=2;result=invalid;seq=2;cause=anchor")
    );
}

#[tokio::test]
async fn a_failing_log_is_a_storage_error_and_records_nothing() {
    let log = Arc::new(FakeSecurityAuditLog::failing());

    let error = handler_over(&log)
        .handle(query(Vec::new()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(log.recorded(), Vec::new());
}
