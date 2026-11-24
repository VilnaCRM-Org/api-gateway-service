use iam_domain::{
    AuditOutcome, ChangeStatement, DecisionEffect, IamChange, IamUnitOfWork as _, PolicyVersion,
    RepositoryError,
};

use super::{FakeIamUnitOfWork, audit_parts, event_envelope, iam_change, rebuilt, uuid_v7};
use crate::block_on;
use crate::seed::TestRng;

#[test]
fn the_same_seed_gives_equal_changes_and_different_seeds_different_ones() {
    let first = iam_change(&mut TestRng::from_seed(7), DecisionEffect::Affected, 2);
    let second = iam_change(&mut TestRng::from_seed(7), DecisionEffect::Affected, 2);
    let other = iam_change(&mut TestRng::from_seed(8), DecisionEffect::Affected, 2);

    assert_eq!(first, second);
    assert_ne!(first, other);
    assert_eq!(first.parts().events.len(), 2);
    assert!(first.idempotency_record().is_some());
}

#[test]
fn an_envelope_has_a_v7_id_the_given_aggregate_and_a_catalogue_type() {
    let mut rng = TestRng::from_seed(3);
    let aggregate = uuid_v7(&mut rng);

    let envelope = event_envelope(&mut rng, aggregate);

    assert_eq!(envelope.parts().id.as_uuid().get_version_num(), 7);
    assert_eq!(envelope.parts().aggregate_id, aggregate);
    assert_eq!(envelope.parts().event_type.as_str(), "iam.role.updated");
}

#[test]
fn the_new_and_the_default_unit_of_work_start_at_version_0() {
    for unit in [FakeIamUnitOfWork::new(), FakeIamUnitOfWork::default()] {
        assert_eq!(unit.policy_version(), 0);
        assert_eq!(unit.committed(), Vec::<IamChange>::new());
    }
}

#[test]
fn a_change_that_affects_decisions_takes_the_next_version_and_one_that_does_not_keeps_it() {
    let mut rng = TestRng::from_seed(11);
    let affecting = iam_change(&mut rng, DecisionEffect::Affected, 1);
    let neutral = iam_change(&mut rng, DecisionEffect::Unaffected, 1);
    let unit = FakeIamUnitOfWork::new();

    let first = block_on(unit.commit(affecting.clone(), iam_domain::WriteMode::Published)).unwrap();
    let second = block_on(unit.commit(neutral.clone(), iam_domain::WriteMode::Published)).unwrap();

    assert_eq!(first.policy_version(), PolicyVersion::new(1).ok());
    assert_eq!(second.policy_version(), None);
    assert_eq!(unit.policy_version(), 1);
    assert_eq!(unit.committed(), vec![affecting, neutral]);
}

#[test]
fn a_failing_statement_a_reused_key_and_a_reused_change_id_commit_nothing() {
    let mut rng = TestRng::from_seed(12);
    let stored = iam_change(&mut rng, DecisionEffect::Affected, 0);
    let stale = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 0),
        |parts| {
            parts.statements = vec![ChangeStatement::ExpectPolicyVersion(
                PolicyVersion::new(0).unwrap(),
            )];
        },
    );
    let same_key = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 0),
        |parts| {
            parts.audit = stored.parts().audit.clone();
            parts.idempotency = stored.parts().idempotency.clone();
        },
    );
    let same_id = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 0),
        |parts| {
            parts.change_id = stored.parts().change_id;
            parts.idempotency = None;
        },
    );
    let unit = FakeIamUnitOfWork::new();
    block_on(unit.commit(stored.clone(), iam_domain::WriteMode::Published)).unwrap();

    let conflict = block_on(unit.commit(stale, iam_domain::WriteMode::Published)).unwrap_err();
    let duplicate_key =
        block_on(unit.commit(same_key, iam_domain::WriteMode::Published)).unwrap_err();
    let duplicate_id =
        block_on(unit.commit(same_id, iam_domain::WriteMode::Published)).unwrap_err();

    assert!(matches!(conflict, RepositoryError::Conflict));
    assert!(matches!(duplicate_key, RepositoryError::AlreadyExists));
    assert!(matches!(duplicate_id, RepositoryError::AlreadyExists));
    assert_eq!(unit.committed(), vec![stored]);
    assert_eq!(unit.policy_version(), 1);
}

#[test]
fn the_failing_unit_of_work_is_unavailable_and_holds_nothing() {
    let change = iam_change(&mut TestRng::from_seed(13), DecisionEffect::Affected, 0);
    let unit = FakeIamUnitOfWork::failing();

    let error = block_on(unit.commit(change, iam_domain::WriteMode::Published)).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(unit.committed(), Vec::<IamChange>::new());
    assert_eq!(unit.policy_version(), 0);
}

#[test]
fn the_audit_values_rebuild_a_change_and_a_rejected_record_is_refused() {
    let change = iam_change(&mut TestRng::from_seed(14), DecisionEffect::Affected, 0);
    let mut parts = audit_parts(&change);
    parts.outcome = AuditOutcome::Rejected;
    let rejected = iam_domain::SecurityAuditEvent::record(parts).unwrap();

    let refused = IamChange::new(iam_domain::IamChangeParts {
        audit: rejected,
        ..change.parts().clone()
    });

    assert_eq!(audit_parts(&change), change.parts().audit.parts().clone());
    assert!(refused.is_err());
}
