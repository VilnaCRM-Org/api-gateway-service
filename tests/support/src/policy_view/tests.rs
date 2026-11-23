use std::sync::Arc;

use iam_domain::{PolicyVersion, PolicyView as _, RoleId, SubjectRef};
use shared_domain::Uuid;

use super::{EmptySnapshot, FakePolicyView};

fn nil() -> Uuid {
    Uuid::parse("00000000-0000-0000-0000-000000000000").unwrap()
}

#[test]
fn a_new_view_hands_out_an_empty_snapshot_at_version_zero() {
    let view = FakePolicyView::new();

    let snapshot = view.current().unwrap();

    assert_eq!(snapshot.version(), PolicyVersion::ZERO);
    assert_eq!(snapshot.freshness_proof().version, PolicyVersion::ZERO);
    assert!(snapshot.role_set(RoleId::from_uuid(nil())).is_none());
    assert_eq!(snapshot.assignments(&SubjectRef::user(nil())), []);
    let no_subjects: [SubjectRef; 0] = [];
    assert_eq!(
        snapshot.subjects_of_role(RoleId::from_uuid(nil())),
        no_subjects
    );
}

#[test]
fn a_failing_view_has_no_snapshot() {
    assert!(FakePolicyView::failing().current().is_none());
}

#[test]
fn a_view_hands_out_the_snapshot_it_was_given() {
    let version = PolicyVersion::new(7).unwrap();
    let view = FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(version)));

    assert_eq!(view.current().unwrap().version(), version);
    assert_eq!(
        FakePolicyView::default().current().unwrap().version(),
        PolicyVersion::ZERO
    );
}
