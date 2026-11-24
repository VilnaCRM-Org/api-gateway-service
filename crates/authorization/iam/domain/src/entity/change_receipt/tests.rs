use shared_domain::Uuid;

use super::ChangeReceipt;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::ChangeId;
use crate::value_object::policy_version::PolicyVersion;

#[test]
fn a_receipt_keeps_the_change_its_target_and_both_versions() {
    let change_id = ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap();
    let actor = ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap());
    let target = AuditTarget::new("role", "r-1").unwrap();
    let version = EntityVersion::new(4).unwrap();
    let policy = PolicyVersion::new(9).ok();

    let receipt = ChangeReceipt::new(change_id, actor.clone(), target.clone(), version, policy);

    assert_eq!(receipt.change_id(), change_id);
    assert_eq!(receipt.actor(), &actor);
    assert_eq!(receipt.target(), &target);
    assert_eq!(receipt.entity_version(), version);
    assert_eq!(receipt.policy_version(), policy);
}

#[test]
fn a_receipt_reports_no_revoked_assignments_until_it_is_given_a_count() {
    let receipt = ChangeReceipt::new(
        ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap(),
        ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()),
        AuditTarget::new("role", "r-1").unwrap(),
        EntityVersion::new(4).unwrap(),
        PolicyVersion::new(9).ok(),
    );

    assert_eq!(receipt.revoked_assignments(), None);
    assert_eq!(
        receipt.with_revoked_assignments(3).revoked_assignments(),
        Some(3)
    );
}

#[test]
fn a_receipt_carries_the_propagation_outcome_it_is_given() {
    use crate::value_object::propagation_outcome::PropagationOutcome;

    let receipt = ChangeReceipt::new(
        ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap(),
        ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()),
        AuditTarget::new("role", "r-1").unwrap(),
        EntityVersion::new(4).unwrap(),
        PolicyVersion::new(9).ok(),
    );

    assert_eq!(receipt.propagation(), None);
    assert_eq!(
        receipt
            .with_propagation(PropagationOutcome::Published { offset: 12 })
            .propagation(),
        Some(PropagationOutcome::Published { offset: 12 })
    );
}
