use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, IdempotencyKey, IdempotencyRequest, RequestDigest,
};
use shared_domain::Uuid;
use test_support::id::SequenceUuidGenerator;

use super::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use crate::error::IamError;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const TARGET: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn record<'a>(
    actor: &'a ActorRef,
    kind: &'static str,
    idempotency: Option<&'a IdempotencyRequest>,
) -> ChangeRecord<'a> {
    ChangeRecord {
        action: "upstream.update",
        kind,
        target_id: TARGET.to_owned(),
        actor,
        occurred_at: at(),
        before: Some("version=1".to_owned()),
        after: "version=2".to_owned(),
        idempotency,
    }
}

#[test]
fn a_committed_record_names_the_actor_the_target_and_both_states() {
    let actor = actor();
    let event = committed(
        &SequenceUuidGenerator::starting_at(1),
        record(&actor, "upstream", None),
    )
    .unwrap();

    let parts = event.parts();
    assert_eq!(parts.action.as_str(), "upstream.update");
    assert_eq!(parts.outcome, AuditOutcome::Committed);
    assert_eq!(parts.actor, actor);
    assert_eq!(parts.target.target_type(), "upstream");
    assert_eq!(parts.target.target_id(), TARGET);
    assert_eq!(parts.occurred_at, at());
    assert_eq!(
        parts.before.as_ref().map(AuditSummary::as_str),
        Some("version=1")
    );
    assert_eq!(
        parts.after.as_ref().map(AuditSummary::as_str),
        Some("version=2")
    );
    assert_eq!(parts.idempotency_key, None);
    assert_eq!(parts.reason, None);
}

#[test]
fn a_creation_has_no_state_before_it_and_keeps_the_idempotency_key() {
    let actor = actor();
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("create-1").unwrap(),
        request_digest: RequestDigest::new(&[7; RequestDigest::LENGTH]).unwrap(),
    };
    let mut creation = record(&actor, "upstream", Some(&request));
    creation.before = None;

    let event = committed(&SequenceUuidGenerator::starting_at(1), creation).unwrap();

    assert_eq!(event.parts().before, None);
    assert_eq!(event.parts().idempotency_key, Some(request.key));
}

#[test]
fn a_record_that_breaks_a_domain_invariant_is_an_internal_failure() {
    let actor = actor();

    let result = committed(
        &SequenceUuidGenerator::starting_at(1),
        record(&actor, "Not A Kind", None),
    );

    assert!(matches!(result, Err(IamError::Internal(_))));
}

#[test]
fn a_refused_system_entry_is_offered_to_the_buffer_as_a_rejected_attempt() {
    let log = FakeRejectedAttemptLog::new();
    let actor = actor();

    let error = refuse_system_entry(
        &log,
        SystemEntryRefusal {
            action: "upstream.delete",
            kind: "upstream",
            target_id: TARGET.to_owned(),
            actor: &actor,
            occurred_at: at(),
        },
    );

    assert!(matches!(error, IamError::SystemEntry));
    let offered = log.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.actor, actor);
    assert_eq!(attempt.action.as_str(), "upstream.delete");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(attempt.target.target_type(), "upstream");
    assert_eq!(attempt.target.target_id(), TARGET);
    assert_eq!(attempt.occurred_at, at());
    assert_eq!(attempt.request_id, None);
}

#[test]
fn a_refusal_that_cannot_be_described_is_an_internal_failure_and_offers_nothing() {
    let log = FakeRejectedAttemptLog::new();
    let actor = actor();

    let error = refuse_system_entry(
        &log,
        SystemEntryRefusal {
            action: "nodot",
            kind: "upstream",
            target_id: TARGET.to_owned(),
            actor: &actor,
            occurred_at: at(),
        },
    );

    assert!(matches!(error, IamError::Internal(_)));
    assert_eq!(log.offered(), Vec::new());
}
