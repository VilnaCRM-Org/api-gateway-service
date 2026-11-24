use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{AttemptSummary, RejectedAttempt, RejectedAttemptBuffer, SUMMARY_WINDOW};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_reason::AuditReason;
use crate::value_object::audit_target::AuditTarget;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user(number: u32) -> Uuid {
    Uuid::parse(&format!("00000000-0000-7000-8000-{number:012}")).unwrap()
}

fn attempt_of(actor: u32, action: &str, seconds: u64) -> RejectedAttempt {
    RejectedAttempt {
        actor: ActorRef::User(user(actor)),
        action: AuditAction::new(action).unwrap(),
        reason: AuditReason::new("forbidden").unwrap(),
        target: AuditTarget::new("operation", action).unwrap(),
        occurred_at: at(seconds),
        request_id: None,
    }
}

#[test]
fn a_thousand_identical_refusals_are_one_summary_with_their_count() {
    let mut buffer = RejectedAttemptBuffer::new();
    for second in 0..1000 {
        buffer.offer(attempt_of(1, "role.create", second % 60));
    }

    let summaries = buffer.drain(at(60));

    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].count(), 1000);
    assert_eq!(summaries[0].first().occurred_at, at(0));
}

#[test]
fn refusals_that_differ_by_actor_or_action_are_separate_summaries() {
    let mut buffer = RejectedAttemptBuffer::new();
    buffer.offer(attempt_of(1, "role.create", 1));
    buffer.offer(attempt_of(2, "role.create", 2));
    buffer.offer(attempt_of(1, "role.delete", 3));

    let summaries = buffer.drain(at(4));

    assert_eq!(summaries.len(), 3);
    assert!(summaries.iter().all(|summary| summary.count() == 1));
    let times: Vec<_> = summaries
        .iter()
        .map(|summary| summary.first().occurred_at)
        .collect();
    assert_eq!(times, vec![at(1), at(2), at(3)]);
}

#[test]
fn the_first_refusal_is_due_at_once_and_the_rest_wait_for_the_window_to_end() {
    let mut buffer = RejectedAttemptBuffer::new();
    buffer.offer(attempt_of(1, "role.create", 0));
    assert_eq!(buffer.drain(at(1))[0].count(), 1);

    buffer.offer(attempt_of(1, "role.create", 2));
    buffer.offer(attempt_of(1, "role.create", 3));
    assert_eq!(buffer.drain(at(4)).len(), 0);
    assert_eq!(buffer.drain(at(59)).len(), 0);

    let summaries = buffer.drain(at(SUMMARY_WINDOW.as_secs()));
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].count(), 2);
    assert_eq!(summaries[0].first().occurred_at, at(2));
}

#[test]
fn a_key_that_stayed_quiet_for_a_window_is_forgotten_and_starts_afresh() {
    let mut buffer = RejectedAttemptBuffer::new();
    buffer.offer(attempt_of(1, "role.create", 0));
    assert_eq!(buffer.drain(at(1)).len(), 1);
    assert_eq!(buffer.len(), 1);

    assert_eq!(buffer.drain(at(61)).len(), 0);
    assert!(buffer.is_empty());

    buffer.offer(attempt_of(1, "role.create", 100));
    assert_eq!(buffer.drain(at(101))[0].count(), 1);
}

#[test]
fn a_refusal_after_a_quiet_window_is_due_at_once_even_before_the_slot_is_forgotten() {
    let mut buffer = RejectedAttemptBuffer::new();
    buffer.offer(attempt_of(1, "role.create", 0));
    assert_eq!(buffer.drain(at(1)).len(), 1);

    buffer.offer(attempt_of(1, "role.create", 70));

    let summaries = buffer.drain(at(71));
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].first().occurred_at, at(70));
}

#[test]
fn requeued_summaries_are_due_at_the_next_drain_and_keep_their_count() {
    let mut buffer = RejectedAttemptBuffer::new();
    buffer.offer(attempt_of(1, "role.create", 0));
    buffer.offer(attempt_of(1, "role.create", 1));
    let taken = buffer.drain(at(2));
    assert_eq!(taken[0].count(), 2);

    buffer.requeue(taken);
    buffer.offer(attempt_of(1, "role.create", 3));

    let again = buffer.drain(at(4));
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].count(), 3);
    assert_eq!(again[0].first().occurred_at, at(0));
}

#[test]
fn a_requeued_summary_of_a_forgotten_key_is_restored() {
    let mut buffer = RejectedAttemptBuffer::new();
    let summary = AttemptSummary::new(attempt_of(7, "role.delete", 5), 4);

    buffer.requeue(vec![summary.clone()]);

    assert_eq!(buffer.drain(at(6)), vec![summary]);
}

#[test]
fn a_summary_reports_its_first_refusal_and_count() {
    let first = attempt_of(1, "role.create", 0);

    let summary = AttemptSummary::new(first.clone(), 9);

    assert_eq!(summary.first(), &first);
    assert_eq!(summary.count(), 9);
}
