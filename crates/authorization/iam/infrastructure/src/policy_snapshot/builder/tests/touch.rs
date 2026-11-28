//! What the publications of the builder say the versions touched (Story 11.2).

use std::time::Duration;

use iam_domain::LogEpoch;

use super::history::raw_entries;
use super::support::{Rig, role, role_key, route, route_id, subject, subject_ref, version};

#[test]
fn a_publication_names_the_roles_subjects_and_routes_its_version_changed() {
    let mut rig = Rig::new();
    rig.apply(vec![
        role(1, &["rest:cat-0:*"]),
        subject(1, &[1]),
        route(1, "api.example.com"),
    ]);

    let change = rig.builder.take_published().unwrap();

    assert_eq!(change.version, version(1));
    assert!(change.touch.subjects().contains(&subject_ref(1)));
    assert_eq!(change.touch.subjects().len(), 1);
    assert_eq!(change.touch.roles().len(), 1);
    assert!(change.touch.routes().contains(&route_id(1)));
    assert!(!change.touch.touches_everything());
}

#[test]
fn a_publication_is_taken_once() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:*"])]);

    assert!(rig.builder.take_published().is_some());
    assert!(rig.builder.take_published().is_none());
}

#[test]
fn nothing_is_taken_before_a_snapshot_is_published() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:*"])]);
    rig.builder.take_published();
    rig.apply(vec![subject(1, &[1])]);

    assert!(
        rig.builder.take_published().is_none(),
        "the second version waits for the interval"
    );
}

#[test]
fn the_versions_a_publication_covers_add_up_their_touches() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:*"])]);
    rig.builder.take_published();
    rig.apply(vec![subject(1, &[1])]);
    rig.apply(vec![route(1, "api.example.com")]);
    rig.builder.flush();

    let change = rig.builder.take_published().unwrap();

    assert_eq!(change.version, version(3));
    assert!(change.touch.roles().is_empty(), "the role was in version 1");
    assert!(change.touch.subjects().contains(&subject_ref(1)));
    assert!(change.touch.routes().contains(&route_id(1)));
}

#[test]
fn publications_that_were_not_taken_are_joined() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:*"])]);
    rig.clock.advance(Duration::from_millis(10));
    rig.apply(vec![subject(1, &[1])]);

    let change = rig.builder.take_published().unwrap();

    assert_eq!(change.version, version(2));
    assert_eq!(change.touch.roles().len(), 1);
    assert!(change.touch.subjects().contains(&subject_ref(1)));
    assert!(rig.builder.take_published().is_none());
}

#[test]
fn a_state_installed_as_a_whole_touches_everything() {
    let mut source = Rig::new();
    source.apply(vec![role(1, &["rest:cat-0:*"])]);
    source.builder.flush();
    let mut rig = Rig::new();
    rig.builder
        .rebuild(
            &raw_entries(&source),
            version(source.version),
            LogEpoch::new(1).unwrap(),
        )
        .unwrap();

    let change = rig.builder.take_published().unwrap();

    assert!(change.touch.touches_everything());
    assert_eq!(change.version, version(1));
}

#[test]
fn a_deleted_role_is_touched_too() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:*"])]);
    rig.builder.take_published();
    rig.clock.advance(Duration::from_millis(10));
    rig.apply(vec![(role_key(1), None)]);

    let change = rig.builder.take_published().unwrap();

    assert_eq!(change.touch.roles().len(), 1);
}
