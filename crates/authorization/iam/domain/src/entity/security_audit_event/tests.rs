use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::{SecurityAuditEvent, SecurityAuditEventParts, StoredSecurityAuditEvent};
use crate::error::InvalidIamValue;
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_hash::AuditHash;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::audit_reason::AuditReason;
use crate::value_object::audit_summary::AuditSummary;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::{ProjectId, SecurityAuditEventId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::request_id::RequestId;
use crate::value_object::service_name::ServiceName;

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f00-00000000000f";
/// 2023-11-14T22:13:20.123456Z.
const MICROS: i64 = 1_700_000_000_123_456;

fn at_micros(micros: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .unwrap()
}

fn minimal() -> SecurityAuditEventParts {
    SecurityAuditEventParts {
        id: SecurityAuditEventId::parse(ID).unwrap(),
        occurred_at: at_micros(1_700_000_000_123_456),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        caller_service: None,
        action: AuditAction::new("role.create").unwrap(),
        target: AuditTarget::new("role", "r-1").unwrap(),
        scope: None,
        before: None,
        after: None,
        idempotency_key: None,
        outcome: AuditOutcome::Rejected,
        reason: None,
        policy_version: None,
        request_id: None,
    }
}

fn complete() -> SecurityAuditEventParts {
    SecurityAuditEventParts {
        caller_service: Some(ServiceName::new("core").unwrap()),
        scope: Some(AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())),
        before: Some(AuditSummary::new("name=readers").unwrap()),
        after: Some(AuditSummary::new("name=writers").unwrap()),
        idempotency_key: Some(IdempotencyKey::new("key-1").unwrap()),
        outcome: AuditOutcome::Committed,
        reason: Some(AuditReason::new("forbidden").unwrap()),
        policy_version: Some(PolicyVersion::new(42).unwrap()),
        request_id: Some(RequestId::new("req-9").unwrap()),
        ..minimal()
    }
}

#[test]
fn a_record_keeps_its_values_and_its_time_in_microseconds() {
    let event = SecurityAuditEvent::record(complete()).unwrap();

    assert_eq!(event.parts(), &complete());
    assert_eq!(event.occurred_at_micros(), MICROS);
}

#[test]
fn the_time_is_truncated_to_whole_microseconds() {
    let precise = at_micros(1_700_000_000_123_456)
        .checked_add(Duration::from_nanos(999))
        .unwrap();

    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        occurred_at: precise,
        ..minimal()
    })
    .unwrap();

    assert_eq!(event.occurred_at_micros(), MICROS);
    assert_eq!(event.parts().occurred_at, at_micros(1_700_000_000_123_456));
}

#[test]
fn a_caller_service_equal_to_the_service_actor_is_dropped() {
    let core = ServiceName::new("core").unwrap();

    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        actor: ActorRef::Service(core.clone()),
        caller_service: Some(core),
        ..minimal()
    })
    .unwrap();

    assert_eq!(event.parts().caller_service, None);
}

#[rstest]
#[case(ActorRef::Service(ServiceName::new("billing").unwrap()))]
#[case(ActorRef::System(SystemComponent::Startup))]
#[case(ActorRef::User(Uuid::parse(USER).unwrap()))]
fn a_caller_service_that_differs_from_the_actor_is_kept(#[case] actor: ActorRef) {
    let core = ServiceName::new("core").unwrap();

    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        actor,
        caller_service: Some(core.clone()),
        ..minimal()
    })
    .unwrap();

    assert_eq!(event.parts().caller_service, Some(core));
}

#[test]
fn a_time_before_1970_is_rejected() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_micros(1))
        .unwrap();

    let error = SecurityAuditEvent::record(SecurityAuditEventParts {
        occurred_at: before,
        ..minimal()
    })
    .unwrap_err();

    assert_eq!(error, InvalidIamValue::AuditTimestamp);
}

#[test]
fn a_time_past_the_largest_microsecond_count_is_rejected() {
    let far = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(i64::MAX).unwrap() / 1_000,
        ))
        .unwrap();

    let error = SecurityAuditEvent::record(SecurityAuditEventParts {
        occurred_at: far,
        ..minimal()
    })
    .unwrap_err();

    assert_eq!(error, InvalidIamValue::AuditTimestamp);
}

#[test]
fn the_epoch_itself_is_microsecond_0() {
    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        occurred_at: SystemTime::UNIX_EPOCH,
        ..minimal()
    })
    .unwrap();

    assert_eq!(event.occurred_at_micros(), 0);
}

#[test]
fn a_restored_record_equals_the_recorded_one() {
    let recorded = SecurityAuditEvent::record(complete()).unwrap();

    let restored = SecurityAuditEvent::restore(
        SecurityAuditEventParts {
            occurred_at: SystemTime::UNIX_EPOCH,
            ..complete()
        },
        MICROS,
    )
    .unwrap();

    assert_eq!(restored, recorded);
    assert_eq!(restored.canonical_form(), recorded.canonical_form());
}

#[test]
fn a_negative_stored_time_is_rejected() {
    assert_eq!(
        SecurityAuditEvent::restore(minimal(), -1),
        Err(InvalidIamValue::AuditTimestamp)
    );
}

#[test]
fn the_canonical_form_lists_every_value_in_a_fixed_order() {
    let event = SecurityAuditEvent::record(complete()).unwrap();

    assert_eq!(
        event.canonical_form(),
        format!(
            "iam.security_audit.v1\nid={ID}\noccurred_at={MICROS}\nactor=user:{USER}\n\
             caller_service=core\naction=role.create\ntarget_type=role\ntarget_id=r-1\n\
             scope=project:{PROJECT}\nbefore=name=readers\nafter=name=writers\n\
             idempotency_key=key-1\noutcome=committed\nreason=forbidden\npolicy_version=42\n\
             request_id=req-9"
        )
    );
}

#[test]
fn the_canonical_form_writes_absent_values_as_nothing() {
    let event = SecurityAuditEvent::record(minimal()).unwrap();

    assert_eq!(
        event.canonical_form(),
        format!(
            "iam.security_audit.v1\nid={ID}\noccurred_at={MICROS}\nactor=user:{USER}\n\
             caller_service=\naction=role.create\ntarget_type=role\ntarget_id=r-1\nscope=\n\
             before=\nafter=\nidempotency_key=\noutcome=rejected\nreason=\npolicy_version=\n\
             request_id="
        )
    );
}

#[test]
fn records_that_differ_in_one_value_have_different_canonical_forms() {
    let first = SecurityAuditEvent::record(complete()).unwrap();
    let second = SecurityAuditEvent::record(SecurityAuditEventParts {
        policy_version: Some(PolicyVersion::new(43).unwrap()),
        ..complete()
    })
    .unwrap();

    assert_ne!(first.canonical_form(), second.canonical_form());
}

#[rstest]
#[case(1)]
#[case(i64::MAX)]
fn a_stored_record_keeps_its_place_in_the_chain(#[case] seq: i64) {
    let event = SecurityAuditEvent::record(minimal()).unwrap();
    let prev_hash = AuditHash::new(&[1; 32]).unwrap();
    let hash = AuditHash::new(&[2; 32]).unwrap();

    let stored = StoredSecurityAuditEvent::new(seq, event.clone(), prev_hash, hash).unwrap();

    assert_eq!(stored.seq(), seq);
    assert_eq!(stored.event(), &event);
    assert_eq!(stored.prev_hash(), prev_hash);
    assert_eq!(stored.hash(), hash);
}

#[rstest]
#[case(0)]
#[case(-1)]
fn a_stored_record_below_sequence_1_is_rejected(#[case] seq: i64) {
    let event = SecurityAuditEvent::record(minimal()).unwrap();

    assert_eq!(
        StoredSecurityAuditEvent::new(seq, event, AuditHash::GENESIS, AuditHash::GENESIS),
        Err(InvalidIamValue::AuditSequence)
    );
}

#[test]
fn a_record_stamped_with_a_policy_version_differs_only_in_that_version() {
    let event = SecurityAuditEvent::record(complete()).unwrap();
    let version = PolicyVersion::new(7).ok();

    let stamped = event.with_policy_version(version);
    let cleared = event.with_policy_version(None);

    assert_eq!(stamped.parts().policy_version, version);
    assert_eq!(cleared.parts().policy_version, None);
    assert_eq!(
        stamped.with_policy_version(event.parts().policy_version),
        event
    );
    assert!(stamped.canonical_form().contains("\npolicy_version=7\n"));
    assert!(cleared.canonical_form().contains("\npolicy_version=\n"));
}
