use std::sync::Arc;

use iam_domain::{AuditOutcome, SecurityAuditEventId, SecurityAuditLog};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{AUDIT_ACTION, GetSecurityAuditEventQuery, GetSecurityAuditEventQueryHandler};
use crate::error::IamError;
use crate::security_audit_fixtures::{actor, at, record, uuid};

async fn seeded() -> Arc<FakeSecurityAuditLog> {
    let log = Arc::new(FakeSecurityAuditLog::new());
    for (seq, outcome) in [(1, AuditOutcome::Committed), (2, AuditOutcome::Rejected)] {
        let record = record(seq, outcome);
        log.append_batch(std::slice::from_ref(record.event()))
            .await
            .unwrap();
    }
    log
}

fn handler_over(log: &Arc<FakeSecurityAuditLog>) -> GetSecurityAuditEventQueryHandler {
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    GetSecurityAuditEventQueryHandler::new(
        port,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(SequenceUuidGenerator::starting_at(1_000)),
    )
}

fn query(id: u64) -> GetSecurityAuditEventQuery {
    GetSecurityAuditEventQuery {
        actor: actor(),
        id: SecurityAuditEventId::from_uuid(uuid(id)),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetSecurityAuditEventQuery::NAME,
        "GetSecurityAuditEventQuery"
    );
}

#[tokio::test]
async fn a_stored_record_is_answered_with_its_place_in_the_chain() {
    let log = seeded().await;

    let answer = handler_over(&log).handle(query(2)).await.unwrap().unwrap();

    assert_eq!(answer.seq(), 2);
    assert_eq!(answer.event().parts().outcome, AuditOutcome::Rejected);
}

#[tokio::test]
async fn a_successful_read_is_recorded_under_the_id_that_was_read() {
    let log = seeded().await;

    handler_over(&log).handle(query(1)).await.unwrap();

    let recorded = log.recorded();
    assert_eq!(recorded.len(), 3);
    let parts = recorded[2].event().parts();
    assert_eq!(parts.actor, actor());
    assert_eq!(parts.action.as_str(), AUDIT_ACTION);
    assert_eq!(parts.target.target_id(), uuid(1).to_string());
    assert_eq!(parts.after.as_ref().unwrap().as_str(), "seq=1");
    assert_eq!(parts.outcome, AuditOutcome::Committed);
}

#[tokio::test]
async fn an_unknown_record_is_answered_with_none_and_nothing_is_recorded() {
    let log = seeded().await;

    let answer = handler_over(&log).handle(query(255)).await.unwrap();

    assert_eq!(answer, None);
    assert_eq!(log.recorded().len(), 2);
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_query() {
    let log = Arc::new(FakeSecurityAuditLog::failing());

    let error = handler_over(&log).handle(query(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_read_that_cannot_be_audited_is_not_served() {
    let log = seeded().await;
    let record = log.recorded().remove(0);
    // A log that finds the record but cannot append: the generator repeats the id of record 1.
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(&log);
    let handler = GetSecurityAuditEventQueryHandler::new(
        port,
        Arc::new(FixedClock::at(at(900))),
        Arc::new(RepeatingGenerator(record.event().parts().id.as_uuid())),
    );

    let error = handler.handle(query(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
}

#[derive(Debug)]
struct RepeatingGenerator(shared_domain::Uuid);

impl shared_domain::UuidGenerator for RepeatingGenerator {
    fn generate(&self) -> shared_domain::Uuid {
        self.0
    }
}
