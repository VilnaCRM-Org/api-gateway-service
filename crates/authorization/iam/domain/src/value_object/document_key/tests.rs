use super::DocumentKey;
use crate::value_object::policy_version::PolicyVersion;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn the_same_inputs_give_the_same_key() {
    let first = DocumentKey::of("{ a }", Some("Op"), version(3));
    let second = DocumentKey::of("{ a }", Some("Op"), version(3));

    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn another_operation_name_gives_another_key() {
    let named = DocumentKey::of("{ a }", Some("A"), version(3));

    assert_ne!(named, DocumentKey::of("{ a }", Some("B"), version(3)));
    assert_ne!(named, DocumentKey::of("{ a }", None, version(3)));
    assert_ne!(
        DocumentKey::of("{ a }", None, version(3)),
        DocumentKey::of("{ a }", Some(""), version(3))
    );
}

#[test]
fn another_catalogue_version_gives_another_key() {
    assert_ne!(
        DocumentKey::of("{ a }", None, version(3)),
        DocumentKey::of("{ a }", None, version(4))
    );
}

#[test]
fn another_document_gives_another_key() {
    assert_ne!(
        DocumentKey::of("{ a }", None, version(3)),
        DocumentKey::of("{ b }", None, version(3))
    );
}

#[test]
fn a_forced_collision_is_told_apart_by_the_full_text() {
    let first = DocumentKey::from_digest(7);
    let second = DocumentKey::from_digest(7);

    assert_eq!(first, second);
    assert!(first.confirms(second, "{ a }", "{ a }"));
    assert!(!first.confirms(second, "{ a }", "{ b }"));
}

#[test]
fn different_keys_never_confirm_even_for_equal_text() {
    let first = DocumentKey::of("{ a }", Some("A"), version(3));
    let other_operation = DocumentKey::of("{ a }", Some("B"), version(3));
    let other_version = DocumentKey::of("{ a }", Some("A"), version(4));

    assert!(!first.confirms(other_operation, "{ a }", "{ a }"));
    assert!(!first.confirms(other_version, "{ a }", "{ a }"));
}
