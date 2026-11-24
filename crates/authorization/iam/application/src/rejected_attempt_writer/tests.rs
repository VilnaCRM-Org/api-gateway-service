use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditReason, AuditTarget, RejectedAttempt,
    RejectedAttemptLog as _,
};
use shared_domain::Uuid;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::security_audit::FakeSecurityAuditLog;
use tokio::sync::watch;

use super::{FLUSH_INTERVAL, FlushOutcome, RejectedAttemptWriter};
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;

const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn attempt(action: &str) -> RejectedAttempt {
    RejectedAttempt {
        actor: ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        action: AuditAction::new(action).unwrap(),
        reason: AuditReason::new("forbidden").unwrap(),
        target: AuditTarget::new("operation", action).unwrap(),
        occurred_at: at(NOW),
        request_id: None,
    }
}

fn writer(
    log: &Arc<FakeRejectedAttemptLog>,
    audit: &Arc<FakeSecurityAuditLog>,
) -> RejectedAttemptWriter {
    RejectedAttemptWriter::new(
        Arc::<FakeRejectedAttemptLog>::clone(log),
        Arc::<FakeSecurityAuditLog>::clone(audit),
        Arc::new(FixedClock::at(at(NOW + 1))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[tokio::test]
async fn a_thousand_identical_refusals_become_one_record_with_their_count() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());
    for _ in 0..1000 {
        log.offer(attempt("role.create"));
    }

    let outcome = writer(&log, &audit).flush().await;

    assert_eq!(outcome, FlushOutcome::Appended(1));
    let recorded = audit.recorded();
    assert_eq!(recorded.len(), 1);
    let parts = recorded[0].event().parts();
    assert_eq!(parts.outcome, AuditOutcome::Rejected);
    assert_eq!(parts.action.as_str(), "role.create");
    assert_eq!(
        parts.reason.as_ref().map(AuditReason::as_str),
        Some("forbidden")
    );
    assert_eq!(
        parts.after.as_ref().map(iam_domain::AuditSummary::as_str),
        Some("attempts=1000")
    );
    assert_eq!(
        parts.actor.to_string(),
        "user:0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    );
}

#[tokio::test]
async fn different_actions_are_appended_in_one_batch() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());
    log.offer(attempt("role.create"));
    log.offer(attempt("role.delete"));

    let outcome = writer(&log, &audit).flush().await;

    assert_eq!(outcome, FlushOutcome::Appended(2));
    assert_eq!(audit.recorded().len(), 2);
}

#[tokio::test]
async fn a_flush_with_nothing_due_writes_nothing() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());

    let outcome = writer(&log, &audit).flush().await;

    assert_eq!(outcome, FlushOutcome::Idle);
    assert_eq!(audit.recorded().len(), 0);
}

#[tokio::test]
async fn a_failed_append_puts_the_summaries_back_for_the_next_flush() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::failing());
    log.offer(attempt("role.create"));
    log.offer(attempt("role.create"));

    let outcome = writer(&log, &audit).flush().await;

    assert_eq!(outcome, FlushOutcome::Failed);
    let kept = log.drain(at(NOW + 1));
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].count(), 2);
}

#[tokio::test]
async fn a_summary_that_cannot_become_a_record_is_dropped_with_a_failed_flush() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let mut refused = attempt("role.create");
    refused.occurred_at = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();
    log.offer(refused);

    let outcome = writer(&log, &audit).flush().await;

    assert_eq!(outcome, FlushOutcome::Failed);
    assert_eq!(audit.recorded().len(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_loop_flushes_every_interval_and_once_more_when_it_stops() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let (stop, stopping) = watch::channel(false);
    let task = tokio::spawn(writer(&log, &audit).run(stopping));
    tokio::task::yield_now().await;

    log.offer(attempt("role.create"));
    tokio::time::sleep(FLUSH_INTERVAL + Duration::from_millis(1)).await;
    assert_eq!(audit.recorded().len(), 1);

    log.offer(attempt("role.delete"));
    stop.send(true).unwrap();
    task.await.unwrap();

    assert_eq!(audit.recorded().len(), 2);
}
