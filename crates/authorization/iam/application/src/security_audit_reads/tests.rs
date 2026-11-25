use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, SecurityAuditFilter, SecurityAuditLog, SystemComponent,
};
use rstest::rstest;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{ReadAudit, ReadRecord, SEARCH_TARGET_ID, TARGET_TYPE, search_summary};
use crate::error::IamError;
use crate::security_audit_fixtures::{actor, at};

fn audit(log: &Arc<FakeSecurityAuditLog>) -> ReadAudit {
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(log);
    ReadAudit::new(
        port,
        Arc::new(FixedClock::at(at(90))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn read<'a>(actor: &'a ActorRef, target_id: &'a str) -> ReadRecord<'a> {
    ReadRecord {
        actor,
        action: "security_audit.list",
        target_id,
        summary: AuditSummary::new("limit=30").unwrap(),
    }
}

#[tokio::test]
async fn a_read_is_recorded_as_a_committed_event_of_its_actor() {
    let log = Arc::new(FakeSecurityAuditLog::new());
    let actor = actor();

    audit(&log)
        .record(read(&actor, SEARCH_TARGET_ID))
        .await
        .unwrap();

    let recorded = log.recorded();
    assert_eq!(recorded.len(), 1);
    let parts = recorded[0].event().parts();
    assert_eq!(parts.actor, actor);
    assert_eq!(parts.action.as_str(), "security_audit.list");
    assert_eq!(parts.target.target_type(), TARGET_TYPE);
    assert_eq!(parts.target.target_id(), SEARCH_TARGET_ID);
    assert_eq!(parts.outcome, AuditOutcome::Committed);
    assert_eq!(parts.occurred_at, at(90));
    assert_eq!(
        parts.after.as_ref().map(AuditSummary::as_str),
        Some("limit=30")
    );
    assert!(parts.before.is_none());
    assert!(parts.policy_version.is_none());
}

#[tokio::test]
async fn a_log_that_cannot_be_written_fails_the_read() {
    let log = Arc::new(FakeSecurityAuditLog::failing());

    let error = audit(&log)
        .record(read(&actor(), SEARCH_TARGET_ID))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[rstest]
#[case::an_action_that_is_not_dotted("search", SEARCH_TARGET_ID)]
#[case::a_target_that_is_empty("security_audit.list", "")]
#[tokio::test]
async fn a_value_that_breaks_an_invariant_is_an_internal_error(
    #[case] action: &'static str,
    #[case] target_id: &str,
) {
    let log = Arc::new(FakeSecurityAuditLog::new());
    let actor = ActorRef::System(SystemComponent::Startup);
    let record = ReadRecord {
        action,
        ..read(&actor, target_id)
    };

    let error = audit(&log).record(record).await.unwrap_err();

    assert!(matches!(error, IamError::Internal(_)));
    assert_eq!(log.recorded().len(), 0);
}

#[tokio::test]
async fn a_clock_before_1970_is_an_internal_error_and_nothing_is_written() {
    let log = Arc::new(FakeSecurityAuditLog::new());
    let port: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(&log);
    let before_1970 = std::time::UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap();
    let audit = ReadAudit::new(
        port,
        Arc::new(FixedClock::at(before_1970)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let actor = actor();

    let error = audit
        .record(read(&actor, SEARCH_TARGET_ID))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Internal(_)));
    assert_eq!(log.recorded().len(), 0);
}

#[test]
fn a_search_without_conditions_is_summarised_by_its_page_size() {
    let summary = search_summary(&SecurityAuditFilter::new(), 30, None).unwrap();

    assert_eq!(summary.as_str(), "limit=30");
}

#[test]
fn every_condition_of_a_search_is_summarised_in_a_fixed_order() {
    let filter = SecurityAuditFilter::new()
        .within(Some(at(1)), Some(at(2)))
        .unwrap()
        .by_actor(actor())
        .of_action(iam_domain::AuditAction::new("role.update").unwrap())
        .with_outcome(AuditOutcome::Rejected)
        .about("role", Some("r-1"))
        .unwrap();

    let summary = search_summary(&filter, 5, Some(9)).unwrap();

    assert_eq!(
        summary.as_str(),
        format!(
            "limit=5;before=9;from={};until={};actor={};action=role.update;target_type=role;target_id=r-1;outcome=rejected",
            filter.since_micros().unwrap(),
            filter.until_micros().unwrap(),
            actor()
        )
    );
}

#[test]
fn a_condition_that_looks_like_a_token_is_not_written_down() {
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
    let filter = SecurityAuditFilter::new()
        .about("role", Some(token))
        .unwrap();

    let summary = search_summary(&filter, 30, None).unwrap();

    assert_eq!(summary.as_str(), "filter=unsummarised");
}

#[tokio::test]
async fn a_read_of_another_target_type_is_recorded_under_that_type() {
    let log = Arc::new(FakeSecurityAuditLog::new());
    let actor = actor();

    audit(&log)
        .record_about("access_decision", read(&actor, SEARCH_TARGET_ID))
        .await
        .unwrap();

    let recorded = log.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].event().parts().target.target_type(),
        "access_decision"
    );
}
