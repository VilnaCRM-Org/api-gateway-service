use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion,
    PropagationOutcome, WriteMode,
};
use shared_domain::Uuid;

use super::{STATUS_COMMITTED_PENDING, STATUS_PUBLISHED, WriteOutcomeMapper, write_mode};

fn receipt() -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap(),
        ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()),
        AuditTarget::new("role", "r-1").unwrap(),
        EntityVersion::new(4).unwrap(),
        PolicyVersion::new(9).ok(),
    )
}

#[test]
fn a_published_receipt_maps_to_the_published_status_and_its_version() {
    let published = receipt().with_propagation(PropagationOutcome::Published { offset: 3 });

    let propagation = WriteOutcomeMapper::propagation(&published).unwrap();

    assert_eq!(propagation.status, STATUS_PUBLISHED);
    assert_eq!(propagation.policy_version, Some(9));
    assert_eq!(propagation.pods_acknowledged, None);
    assert_eq!(propagation.pods_timed_out, None);
}

#[test]
fn a_pending_receipt_maps_to_the_committed_pending_status() {
    let pending = receipt().with_propagation(PropagationOutcome::CommittedPending);

    let propagation = WriteOutcomeMapper::propagation(&pending).unwrap();

    assert_eq!(propagation.status, STATUS_COMMITTED_PENDING);
    assert_eq!(propagation.policy_version, Some(9));
}

#[test]
fn a_receipt_without_an_outcome_has_no_propagation() {
    assert_eq!(WriteOutcomeMapper::propagation(&receipt()), None);
}

#[test]
fn an_absent_consistency_is_published() {
    assert_eq!(write_mode(None).unwrap(), WriteMode::Published);
    assert_eq!(write_mode(Some("PUBLISHED")).unwrap(), WriteMode::Published);
}

#[test]
fn the_propagated_consistency_is_refused_naming_the_mode() {
    let problem = write_mode(Some("PROPAGATED")).unwrap_err();

    assert_eq!(problem.status, 422);
    assert_eq!(problem.violations[0].property_path, "consistency");
    assert!(problem.violations[0].message.contains("propagated"));
}

#[test]
fn an_unknown_consistency_is_a_validation_problem_naming_the_input() {
    let problem = write_mode(Some("eventually")).unwrap_err();

    assert_eq!(problem.status, 422);
    assert_eq!(problem.violations[0].property_path, "consistency");
}
