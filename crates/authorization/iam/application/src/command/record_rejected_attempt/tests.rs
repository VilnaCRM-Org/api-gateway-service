use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditAction, AuditReason, AuditTarget, RejectedAttemptLog as _, RequestId,
};
use shared_domain::{CommandHandler as _, Uuid};
use test_support::clock::FixedClock;

use super::{RecordRejectedAttemptCommand, RecordRejectedAttemptCommandHandler};
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn command() -> RecordRejectedAttemptCommand {
    RecordRejectedAttemptCommand {
        actor: ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        action: AuditAction::new("role.create").unwrap(),
        reason: AuditReason::new("forbidden").unwrap(),
        target: AuditTarget::new("operation", "role.create").unwrap(),
        request_id: Some(RequestId::new("req-1").unwrap()),
    }
}

#[tokio::test]
async fn the_attempt_is_offered_with_the_time_of_the_clock() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let handler = RecordRejectedAttemptCommandHandler::new(
        Arc::<FakeRejectedAttemptLog>::clone(&log),
        Arc::new(FixedClock::at(at(100))),
    );

    handler.handle(command()).await.unwrap();

    let offered = log.offered();
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].occurred_at, at(100));
    assert_eq!(offered[0].action.as_str(), "role.create");
    assert_eq!(offered[0].reason.as_str(), "forbidden");
    assert_eq!(
        offered[0].request_id,
        Some(RequestId::new("req-1").unwrap())
    );
}

#[tokio::test]
async fn a_thousand_identical_commands_are_one_summary_of_the_buffer() {
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let handler = RecordRejectedAttemptCommandHandler::new(
        Arc::<FakeRejectedAttemptLog>::clone(&log),
        Arc::new(FixedClock::at(at(100))),
    );

    for _ in 0..1000 {
        handler.handle(command()).await.unwrap();
    }

    let summaries = log.drain(at(101));
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].count(), 1000);
}
