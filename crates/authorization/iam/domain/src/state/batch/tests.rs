use shared_domain::Uuid;

use super::*;
use crate::state::fakes::{HashDigest, TextCodec};
use crate::state::model::{AssignmentState, GrantState, RoleState, SubjectState};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::subject::SubjectRef;

fn uuid(last: u8) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-0000000000{last:02x}")).unwrap()
}

fn role_state(last: u8, name: &str) -> PolicyState {
    PolicyState::Role(RoleState {
        id: RoleId::from_uuid(uuid(last)),
        name: name.to_owned(),
        description: None,
        kind: RoleKind::Custom,
        version: EntityVersion::new(1).unwrap(),
        grants: vec![GrantState {
            key: "iam:role:read".to_owned(),
            active: true,
        }],
    })
}

fn subject_state(last: u8, roles: &[u8]) -> Option<PolicyState> {
    let global = AssignmentScope::from_parts("global", None).unwrap();
    let assignments: Vec<_> = roles
        .iter()
        .map(|role| AssignmentState {
            role: RoleId::from_uuid(uuid(*role)),
            scope: global,
            expires_at_micros: None,
        })
        .collect();
    (!assignments.is_empty()).then(|| {
        PolicyState::Subject(SubjectState {
            subject: SubjectRef::user(uuid(last)),
            assignments,
        })
    })
}

fn role_change(last: u8, before: Option<PolicyState>, after: Option<PolicyState>) -> StateChange {
    StateChange {
        key: StateKey::Role(RoleId::from_uuid(uuid(last))),
        before,
        after,
    }
}

fn subject_change(last: u8, before: &[u8], after: &[u8]) -> StateChange {
    StateChange {
        key: StateKey::Subject(SubjectRef::user(uuid(last))),
        before: subject_state(last, before),
        after: subject_state(last, after),
    }
}

fn assemble(before: PolicyDigestValue, changes: Vec<StateChange>) -> StateBatch {
    StateBatch::assemble(
        PolicyVersion::new(7).unwrap(),
        before,
        changes,
        (&TextCodec, &HashDigest),
    )
    .unwrap()
}

fn hash_of(key: &StateKey, state: &PolicyState) -> PolicyDigestValue {
    HashDigest.entity_hash(key, &TextCodec.encode(state).unwrap())
}

#[test]
fn a_created_role_is_one_state_row_and_the_head() {
    let state = role_state(1, "editor");
    let key = StateKey::Role(RoleId::from_uuid(uuid(1)));

    let batch = assemble(
        PolicyDigestValue::ZERO,
        vec![role_change(1, None, Some(state.clone()))],
    );

    let [role, head] = batch.rows() else {
        panic!("expected two rows");
    };
    assert_eq!(role.key(), &key);
    assert_eq!(
        role.payload(),
        Some(TextCodec.encode(&state).unwrap().as_str())
    );
    assert_eq!((role.seq(), role.count()), (1, 2));
    assert_eq!(head.key(), &StateKey::Head);
    assert_eq!((head.seq(), head.count()), (2, 2));
    assert_eq!(batch.version(), PolicyVersion::new(7).unwrap());
    assert_eq!(batch.digest(), hash_of(&key, &state));
}

#[test]
fn the_head_carries_the_version_and_the_digest_of_the_batch() {
    let batch = assemble(
        PolicyDigestValue::ZERO,
        vec![role_change(1, None, Some(role_state(1, "editor")))],
    );

    let head = batch.rows().last().unwrap();
    let expected = PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(7).unwrap(),
        digest: batch.digest(),
    });
    assert_eq!(
        head.payload(),
        Some(TextCodec.encode(&expected).unwrap().as_str())
    );
    assert_eq!(head.digest_after(), batch.digest());
}

#[test]
fn a_deleted_role_with_two_assignments_is_a_tombstone_and_two_subjects_without_a_gap() {
    let changes = vec![
        subject_change(0x20, &[1, 2], &[2]),
        role_change(1, Some(role_state(1, "editor")), None),
        subject_change(0x21, &[1], &[]),
    ];

    let batch = assemble(PolicyDigestValue::ZERO, changes);

    let sequence: Vec<_> = batch.rows().iter().map(StateRow::seq).collect();
    assert_eq!(sequence, [1, 2, 3, 4]);
    assert!(batch.rows().iter().all(|row| row.count() == 4));
    let role = batch
        .rows()
        .iter()
        .find(|row| matches!(row.key(), StateKey::Role(_)))
        .unwrap();
    assert_eq!(role.payload(), None);
    let kept = batch
        .rows()
        .iter()
        .find(|row| row.key().to_string().ends_with("20"))
        .unwrap();
    assert!(kept.payload().is_some());
    let emptied = batch
        .rows()
        .iter()
        .find(|row| row.key().to_string().ends_with("21"))
        .unwrap();
    assert_eq!(emptied.payload(), None);
}

#[test]
fn the_last_row_carries_the_digest_that_the_batch_stores() {
    let batch = assemble(
        PolicyDigestValue::new(&[3; 16]).unwrap(),
        vec![
            role_change(1, Some(role_state(1, "a")), Some(role_state(1, "b"))),
            subject_change(0x20, &[], &[1]),
        ],
    );

    assert_eq!(batch.rows().last().unwrap().digest_after(), batch.digest());
}

#[test]
fn the_digest_moves_by_the_old_and_the_new_hash_of_each_entity() {
    let old = role_state(1, "a");
    let new = role_state(1, "b");
    let key = StateKey::Role(RoleId::from_uuid(uuid(1)));
    let before = PolicyDigestValue::new(&[9; 16]).unwrap();

    let batch = assemble(
        before,
        vec![role_change(1, Some(old.clone()), Some(new.clone()))],
    );

    let expected = before
        .combined(hash_of(&key, &old))
        .combined(hash_of(&key, &new));
    assert_eq!(batch.digest(), expected);
}

#[test]
fn an_entity_whose_encoding_does_not_change_writes_no_row() {
    let state = role_state(1, "editor");
    let before = PolicyDigestValue::new(&[5; 16]).unwrap();

    let batch = assemble(
        before,
        vec![role_change(1, Some(state.clone()), Some(state))],
    );

    assert_eq!(batch.rows().len(), 1);
    assert_eq!(batch.rows()[0].key(), &StateKey::Head);
    assert_eq!(batch.digest(), before);
}

#[test]
fn a_nonexistent_entity_that_stays_nonexistent_writes_no_row() {
    let batch = assemble(PolicyDigestValue::ZERO, vec![role_change(1, None, None)]);

    assert_eq!(batch.rows().len(), 1);
    assert_eq!(batch.digest(), PolicyDigestValue::ZERO);
}

#[test]
fn the_order_of_the_entities_does_not_change_the_rows_or_the_digest() {
    let changes = || {
        vec![
            role_change(1, None, Some(role_state(1, "a"))),
            role_change(2, None, Some(role_state(2, "b"))),
            subject_change(0x20, &[], &[1, 2]),
        ]
    };
    let mut reversed = changes();
    reversed.reverse();

    let forward = assemble(PolicyDigestValue::ZERO, changes());
    let backward = assemble(PolicyDigestValue::ZERO, reversed);

    assert_eq!(forward, backward);
}

#[test]
fn a_digest_replayed_from_the_rows_equals_the_digest_of_the_batch() {
    let first = assemble(
        PolicyDigestValue::ZERO,
        vec![role_change(1, None, Some(role_state(1, "a")))],
    );
    let second = assemble(
        first.digest(),
        vec![
            role_change(1, Some(role_state(1, "a")), None),
            role_change(2, None, Some(role_state(2, "b"))),
        ],
    );

    let mut state = BTreeMap::new();
    for row in first.rows().iter().chain(second.rows()) {
        if *row.key() == StateKey::Head {
            continue;
        }
        match row.payload() {
            Some(payload) => state.insert(row.key().clone(), payload.to_owned()),
            None => state.remove(row.key()),
        };
    }
    let replayed = state
        .iter()
        .fold(PolicyDigestValue::ZERO, |digest, (key, payload)| {
            digest.combined(HashDigest.entity_hash(key, payload))
        });

    assert_eq!(replayed, second.digest());
}
