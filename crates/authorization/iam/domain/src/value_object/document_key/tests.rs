use super::DocumentKey;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

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

fn epoch(log_epoch: i64, digest_byte: u8) -> PolicyEpoch {
    PolicyEpoch::new(
        version(3),
        PolicyDigestValue::from_bytes([digest_byte; PolicyDigestValue::LENGTH]),
        LogEpoch::new(log_epoch).unwrap(),
        RelayEpoch::ZERO,
        0,
    )
    .unwrap()
}

#[test]
fn the_log_epoch_and_the_digest_are_part_of_the_key_of_an_epoch() {
    let key = DocumentKey::in_epoch("{ a }", None, &epoch(1, 0));

    assert_eq!(key, DocumentKey::in_epoch("{ a }", None, &epoch(1, 0)));
    assert_ne!(key, DocumentKey::in_epoch("{ a }", None, &epoch(2, 0)));
    assert_ne!(key, DocumentKey::in_epoch("{ a }", None, &epoch(1, 1)));
    assert_ne!(key, DocumentKey::of("{ a }", None, version(3)));
}
