use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::{IamChange, IamChangeParts};
use crate::entity::idempotency_record::IdempotencyRequest;
use crate::entity::security_audit_event::{SecurityAuditEvent, SecurityAuditEventParts};
use crate::error::InvalidIamValue;
use crate::policy::change_guard::GuardCheck;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::change_statement::ChangeStatement;
use crate::value_object::decision_effect::DecisionEffect;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::{ChangeId, SecurityAuditEventId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::request_digest::RequestDigest;
use crate::value_object::service_name::ServiceName;

const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

fn audit(outcome: AuditOutcome) -> SecurityAuditEvent {
    SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::parse("0190f2a8-7b3c-7d4e-8f00-000000000002").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_700_000_000_123_456))
            .unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        caller_service: None,
        action: AuditAction::new("role.update").unwrap(),
        target: AuditTarget::new("role", "r-1").unwrap(),
        scope: None,
        before: None,
        after: None,
        idempotency_key: None,
        outcome,
        reason: None,
        policy_version: PolicyVersion::new(1).ok(),
        request_id: None,
    })
    .unwrap()
}

fn request() -> IdempotencyRequest {
    IdempotencyRequest {
        key: IdempotencyKey::new("key-1").unwrap(),
        request_digest: RequestDigest::new(&[3; 32]).unwrap(),
    }
}

fn parts(effect: DecisionEffect) -> IamChangeParts {
    IamChangeParts {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        effect,
        statements: vec![ChangeStatement::ExpectPolicyVersion(
            PolicyVersion::new(1).unwrap(),
        )],
        events: Vec::new(),
        audit: audit(AuditOutcome::Committed),
        entity_version: EntityVersion::new(2).unwrap(),
        idempotency: Some(request()),
    }
}

#[rstest]
#[case(DecisionEffect::Affected, true, false)]
#[case(DecisionEffect::RevocationClass, true, true)]
fn a_change_that_affects_decisions_carries_the_version_of_its_transaction(
    #[case] effect: DecisionEffect,
    #[case] affects: bool,
    #[case] revocation: bool,
) {
    let change = IamChange::new(parts(effect)).unwrap();
    let version = PolicyVersion::new(8).unwrap();

    let receipt = change.receipt(version);
    let audit = change.audit(version);

    assert_eq!(change.affects_decisions(), affects);
    assert_eq!(change.is_revocation_class(), revocation);
    assert_eq!(change.resulting_policy_version(version), Some(version));
    assert_eq!(receipt.policy_version(), Some(version));
    assert_eq!(receipt.change_id(), ChangeId::parse(CHANGE).unwrap());
    assert_eq!(receipt.actor(), &ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(receipt.target(), &AuditTarget::new("role", "r-1").unwrap());
    assert_eq!(receipt.entity_version(), EntityVersion::new(2).unwrap());
    assert_eq!(audit.parts().policy_version, Some(version));
    assert_eq!(audit.parts().id, change.parts().audit.parts().id);
    assert_eq!(change.occurred_at_micros(), 1_700_000_000_123_456);
}

#[test]
fn a_change_that_does_not_affect_decisions_carries_no_policy_version() {
    let change = IamChange::new(parts(DecisionEffect::Unaffected)).unwrap();
    let version = PolicyVersion::new(8).unwrap();

    assert!(!change.affects_decisions());
    assert!(!change.is_revocation_class());
    assert_eq!(change.resulting_policy_version(version), None);
    assert_eq!(change.receipt(version).policy_version(), None);
    assert_eq!(change.audit(version).parts().policy_version, None);
}

#[test]
fn the_idempotency_record_names_the_actor_and_the_change() {
    let change = IamChange::new(parts(DecisionEffect::Affected)).unwrap();

    let record = change.idempotency_record().unwrap();

    assert_eq!(record.actor(), &ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(record.key(), &request().key);
    assert_eq!(record.request_digest(), request().request_digest);
    assert_eq!(record.change_id(), ChangeId::parse(CHANGE).unwrap());
}

#[test]
fn a_change_without_a_key_has_no_idempotency_record() {
    let change = IamChange::new(IamChangeParts {
        idempotency: None,
        ..parts(DecisionEffect::Affected)
    })
    .unwrap();

    assert_eq!(change.idempotency_record(), None);
}

#[test]
fn a_change_with_a_rejected_audit_record_is_refused() {
    let change = IamChange::new(IamChangeParts {
        audit: audit(AuditOutcome::Rejected),
        ..parts(DecisionEffect::Affected)
    });

    assert_eq!(change, Err(InvalidIamValue::ChangeAuditOutcome));
}

#[test]
fn a_change_reports_no_revoked_assignments_unless_it_names_a_count() {
    let change = IamChange::new(parts(DecisionEffect::Affected)).unwrap();
    let version = PolicyVersion::new(8).unwrap();

    assert_eq!(change.revoked_assignments(), None);
    assert_eq!(change.receipt(version).revoked_assignments(), None);
}

#[test]
fn the_receipt_of_a_change_carries_the_number_of_revoked_assignments() {
    let change = IamChange::new(parts(DecisionEffect::Affected))
        .unwrap()
        .with_revoked_assignments(3);
    let version = PolicyVersion::new(8).unwrap();

    assert_eq!(change.revoked_assignments(), Some(3));
    assert_eq!(change.receipt(version).revoked_assignments(), Some(3));
}

#[test]
fn a_change_writes_its_own_audit_record_before_the_related_ones() {
    let related = SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::parse("0190f2a8-7b3c-7d4e-8f00-000000000003").unwrap(),
        target: AuditTarget::new("user_role", "ur-1").unwrap(),
        policy_version: None,
        ..audit(AuditOutcome::Committed).parts().clone()
    })
    .unwrap();
    let change = IamChange::new(parts(DecisionEffect::Affected))
        .unwrap()
        .with_related_audits(vec![related.clone()])
        .unwrap();
    let version = PolicyVersion::new(8).unwrap();

    let audits = change.audits(version);

    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].parts().id, change.parts().audit.parts().id);
    assert_eq!(audits[1].parts().id, related.parts().id);
    assert_eq!(audits[1].parts().policy_version, Some(version));
}

#[test]
fn a_change_without_related_audits_writes_only_its_own_record() {
    let change = IamChange::new(parts(DecisionEffect::Unaffected)).unwrap();

    let audits = change.audits(PolicyVersion::new(8).unwrap());

    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].parts().policy_version, None);
}

#[test]
fn a_related_audit_record_that_is_not_committed_is_refused() {
    let change = IamChange::new(parts(DecisionEffect::Affected)).unwrap();

    let refused = change.with_related_audits(vec![audit(AuditOutcome::Rejected)]);

    assert_eq!(refused, Err(InvalidIamValue::ChangeAuditOutcome));
}

#[test]
fn a_change_asks_for_no_check_unless_it_names_one() {
    let change = IamChange::new(parts(DecisionEffect::Affected)).unwrap();
    let service = ServiceName::new("core").unwrap();
    let check = GuardCheck::Spec {
        service,
        flag_downgrade: true,
    };

    assert_eq!(change.guard(), None);
    assert_eq!(change.with_guard(check.clone()).guard(), Some(&check));
}

#[test]
fn a_change_can_expect_the_policy_version_its_check_was_decided_against() {
    let change = IamChange::new(parts(DecisionEffect::Affected)).unwrap();

    let expecting = change.expecting_policy_version(PolicyVersion::new(7).unwrap());

    assert_eq!(
        expecting.parts().statements.last(),
        Some(&ChangeStatement::ExpectPolicyVersion(
            PolicyVersion::new(7).unwrap()
        ))
    );
    assert_eq!(expecting.parts().statements.len(), 2);
}
