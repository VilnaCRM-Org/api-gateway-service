use iam_domain::{
    AssignmentScope, AssignmentState, EntityVersion, GrantState, PolicyState, RoleId, RoleKind,
    RoleState, StateKey, SubjectRef, SubjectState,
};
use shared_domain::Uuid;

use super::*;

fn uuid(last: u8) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-0000000000{last:02x}")).unwrap()
}

fn role(grants: &[(&str, bool)]) -> RoleState {
    RoleState {
        id: RoleId::from_uuid(uuid(1)),
        name: "editor".to_owned(),
        description: None,
        kind: RoleKind::Custom,
        version: EntityVersion::INITIAL,
        grants: grants
            .iter()
            .map(|(key, active)| GrantState {
                key: (*key).to_owned(),
                active: *active,
            })
            .collect(),
    }
}

fn assignment(role: u8) -> AssignmentState {
    AssignmentState {
        role: RoleId::from_uuid(uuid(role)),
        scope: AssignmentScope::Global,
        expires_at_micros: None,
    }
}

#[test]
fn a_role_compiles_its_active_grants_only() {
    let state = PolicyState::Role(role(&[
        ("rest:cat-0:GET /users", true),
        ("rest:cat-0:POST /users", false),
    ]));

    let derived = derive(&state, &mut Interner::default()).unwrap();

    let Derived::Role(compiled) = derived else {
        panic!("expected a compiled role set");
    };
    assert_eq!(compiled.key_count(), 1);
}

#[test]
fn a_role_with_an_unparsable_grant_is_refused() {
    let state = PolicyState::Role(role(&[("not a key", true)]));

    assert!(derive(&state, &mut Interner::default()).is_err());
}

#[test]
fn equal_assignment_lists_share_one_allocation() {
    let mut interner = Interner::default();
    let first = interner.intern(&[assignment(1), assignment(2)]);
    let second = interner.intern(&[assignment(1), assignment(2)]);
    let other = interner.intern(&[assignment(3)]);

    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &other));
    assert_eq!(interner.len(), 2);
}

#[test]
fn a_dropped_list_is_interned_again() {
    let mut interner = Interner::default();
    drop(interner.intern(&[assignment(1)]));

    let again = interner.intern(&[assignment(1)]);

    assert_eq!(again.len(), 1);
}

#[test]
fn the_interner_drops_the_lists_that_nobody_holds() {
    let mut interner = Interner::default();
    for number in 0..u32::try_from(PRUNE_FLOOR + 8).unwrap() {
        let list = [AssignmentState {
            role: RoleId::from_uuid(uuid(1)),
            scope: AssignmentScope::Global,
            expires_at_micros: Some(i64::from(number)),
        }];
        drop(interner.intern(&list));
    }

    assert!(interner.len() < PRUNE_FLOOR);
}

#[test]
fn a_subject_stands_for_its_list_and_one_reverse_pair_per_distinct_role() {
    let subject = SubjectRef::user(uuid(9));
    let state = PolicyState::Subject(SubjectState {
        subject: subject.clone(),
        assignments: vec![assignment(1), assignment(1), assignment(2)],
    });
    let derived = derive(&state, &mut Interner::default()).unwrap();

    let items = items(&StateKey::Subject(subject), &state, &derived);

    assert_eq!(items.len(), 3);
    assert_eq!(
        items
            .iter()
            .filter(|item| item.starts_with("reverse|"))
            .count(),
        2
    );
}

#[test]
fn an_entry_without_derived_structure_has_no_item() {
    let state = PolicyState::Role(role(&[]));

    assert_eq!(
        items(&StateKey::Head, &state, &Derived::Nothing),
        Vec::<String>::new()
    );
}
