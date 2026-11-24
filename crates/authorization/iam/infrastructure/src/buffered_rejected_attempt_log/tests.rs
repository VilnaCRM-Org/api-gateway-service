use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditAction, AuditReason, AuditTarget, RejectedAttempt, RejectedAttemptLog as _,
};
use shared_domain::Uuid;

use super::BufferedRejectedAttemptLog;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn attempt(seconds: u64) -> RejectedAttempt {
    RejectedAttempt {
        actor: ActorRef::User(Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap()),
        action: AuditAction::new("role.create").unwrap(),
        reason: AuditReason::new("forbidden").unwrap(),
        target: AuditTarget::new("operation", "role.create").unwrap(),
        occurred_at: at(seconds),
        request_id: None,
    }
}

#[test]
fn identical_offers_drain_as_one_summary_and_requeue_restores_it() {
    let log = BufferedRejectedAttemptLog::new();
    for _ in 0..1000 {
        log.offer(attempt(0));
    }

    let summaries = log.drain(at(1));
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].count(), 1000);
    assert_eq!(log.drain(at(2)).len(), 0);

    log.requeue(summaries);
    let again = log.drain(at(3));
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].count(), 1000);
}

#[test]
fn a_panic_while_the_lock_is_held_does_not_stop_the_log() {
    let log = Arc::new(BufferedRejectedAttemptLog::new());
    let poisoner = Arc::clone(&log);
    let outcome = std::thread::spawn(move || {
        let _held = poisoner.buffer.lock().unwrap();
        panic!("holder panics");
    })
    .join();
    assert!(outcome.is_err());

    log.offer(attempt(0));

    assert_eq!(log.drain(at(1)).len(), 1);
}
