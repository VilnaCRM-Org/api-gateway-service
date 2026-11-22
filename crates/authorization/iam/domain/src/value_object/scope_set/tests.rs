use std::collections::BTreeSet;

use super::ScopeSet;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::ProjectId;

fn project(last: u8) -> ProjectId {
    ProjectId::parse(&format!("00000000-0000-7000-8000-0000000000{last:02x}")).unwrap()
}

#[test]
fn an_empty_set_covers_nothing() {
    let set = ScopeSet::empty();

    assert!(set.is_empty());
    assert!(!set.is_all());
    assert!(!set.covers(project(1)));
    assert_eq!(set, ScopeSet::default());
}

#[test]
fn project_scopes_cover_exactly_their_projects() {
    let set = ScopeSet::empty()
        .with(AssignmentScope::Project(project(1)))
        .with(AssignmentScope::Project(project(2)))
        .with(AssignmentScope::Project(project(1)));

    assert!(!set.is_empty());
    assert!(!set.is_all());
    assert!(set.covers(project(1)));
    assert!(set.covers(project(2)));
    assert!(!set.covers(project(3)));
    assert_eq!(
        set,
        ScopeSet::Projects(BTreeSet::from([project(1), project(2)]))
    );
}

#[test]
fn a_global_scope_turns_the_set_into_all() {
    let set = ScopeSet::empty()
        .with(AssignmentScope::Project(project(1)))
        .with(AssignmentScope::Global);

    assert_eq!(set, ScopeSet::All);
    assert!(set.is_all());
    assert!(!set.is_empty());
    assert!(set.covers(project(9)));
}

#[test]
fn all_stays_all_when_a_project_is_added() {
    let set = ScopeSet::All.with(AssignmentScope::Project(project(1)));

    assert_eq!(set, ScopeSet::All);
}

#[test]
fn all_is_the_identity_of_the_intersection() {
    let projects = ScopeSet::empty()
        .with(AssignmentScope::Project(project(1)))
        .with(AssignmentScope::Project(project(2)));

    assert_eq!(ScopeSet::All.intersect(&ScopeSet::All), ScopeSet::All);
    assert_eq!(ScopeSet::All.intersect(&projects), projects);
    assert_eq!(projects.clone().intersect(&ScopeSet::All), projects);
}

#[test]
fn the_intersection_of_project_sets_keeps_the_common_projects() {
    let left = ScopeSet::empty()
        .with(AssignmentScope::Project(project(1)))
        .with(AssignmentScope::Project(project(2)));
    let right = ScopeSet::empty()
        .with(AssignmentScope::Project(project(2)))
        .with(AssignmentScope::Project(project(3)));

    assert_eq!(
        left.intersect(&right),
        ScopeSet::Projects(BTreeSet::from([project(2)]))
    );
    assert!(
        ScopeSet::empty()
            .with(AssignmentScope::Project(project(1)))
            .intersect(&ScopeSet::empty())
            .is_empty()
    );
}
