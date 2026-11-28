use super::*;

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const USER_ID: &str = "0192f6a0-0000-7000-8000-000000000002";
const ROUTE: &str = "route/0192f6a0-0000-7000-8000-000000000003";

fn key(text: &str) -> StateKey {
    StateKey::parse(text).unwrap()
}

fn touched(keys: &[&str]) -> PolicyTouch {
    let mut touch = PolicyTouch::nothing();
    for text in keys {
        touch.note(&key(text));
    }
    touch
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn it_starts_with_nothing_touched() {
    assert!(PolicyTouch::nothing().is_nothing());
    assert!(!PolicyTouch::nothing().touches_everything());
}

#[test]
fn it_sorts_each_record_under_what_a_stream_is_bound_to() {
    let touch = touched(&[
        ROLE,
        &format!("subject/user/{USER_ID}"),
        "subject/service/billing",
        "catalog/user-service/manifest",
        "catalog/orders/1/00ff00ff00ff00ff00ff00ff00ff00ff",
        ROUTE,
        "revocation/session/abc",
    ]);

    assert_eq!(touch.roles().len(), 1);
    assert_eq!(touch.subjects().len(), 2);
    assert_eq!(touch.services().len(), 2);
    assert_eq!(touch.routes().len(), 1);
    assert_eq!(touch.sessions().len(), 1);
    assert!(!touch.touches_everything());
    assert!(!touch.is_nothing());
}

#[test]
fn a_user_cutoff_touches_the_user_as_a_subject() {
    let touch = touched(&[&format!("revocation/user/{USER_ID}")]);

    let expected = SubjectRef::new(crate::SubjectKind::User, USER_ID).unwrap();
    assert!(touch.subjects().contains(&expected));
    assert!(!touch.touches_everything());
}

#[test]
fn a_global_cutoff_touches_everything() {
    let touch = touched(&["revocation/global"]);

    assert!(touch.touches_everything());
}

#[test]
fn an_upstream_a_rate_policy_and_the_head_touch_nothing() {
    let touch = touched(&[
        "upstream/users",
        "ratepolicy/0192f6a0-0000-7000-8000-000000000004",
        "__head",
    ]);

    assert!(touch.is_nothing());
}

#[test]
fn merging_adds_what_the_other_touched() {
    let mut touch = touched(&[ROLE]);
    touch.merge(touched(&[ROUTE, "revocation/global"]));

    assert_eq!(touch.roles().len(), 1);
    assert_eq!(touch.routes().len(), 1);
    assert!(touch.touches_everything());
}

#[test]
fn everything_is_not_nothing() {
    assert!(PolicyTouch::everything().touches_everything());
    assert!(!PolicyTouch::everything().is_nothing());
}

#[test]
fn a_later_publication_moves_the_version_up_and_adds_the_touches() {
    let mut change = PolicyChange {
        version: version(4),
        touch: touched(&[ROLE]),
    };
    change.absorb(PolicyChange {
        version: version(6),
        touch: touched(&[ROUTE]),
    });

    assert_eq!(change.version, version(6));
    assert_eq!(change.touch.roles().len(), 1);
    assert_eq!(change.touch.routes().len(), 1);
}

#[test]
fn an_earlier_publication_never_lowers_the_version() {
    let mut change = PolicyChange {
        version: version(6),
        touch: PolicyTouch::nothing(),
    };
    change.absorb(PolicyChange {
        version: version(4),
        touch: PolicyTouch::nothing(),
    });

    assert_eq!(change.version, version(6));
}
