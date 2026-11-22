use std::path::Path;

use rstest::rstest;

use super::{JwtKeyFileError, JwtKeySet};
use crate::token::test_keys::{TestKey, key_file, scratch_dir};

#[rstest]
#[case(1)]
#[case(2)]
#[case(3)]
fn parses_one_to_three_keys(#[case] count: usize) {
    let keys: Vec<TestKey> = (0..count).map(|_| TestKey::generate()).collect();
    let refs: Vec<&TestKey> = keys.iter().collect();

    let set = JwtKeySet::parse(&key_file(&refs)).unwrap();

    assert_eq!(set.len(), count);
    assert!(!set.is_empty());
    assert_eq!(set.newest_first().count(), count);
    assert_eq!(format!("{set:?}"), format!("JwtKeySet {{ keys: {count} }}"));
}

#[rstest]
#[case("")]
#[case("not a key at all\n")]
fn a_file_without_a_pem_block_has_no_key(#[case] text: &str) {
    assert!(matches!(
        JwtKeySet::parse(text),
        Err(JwtKeyFileError::NoKey)
    ));
}

#[test]
fn a_file_with_four_keys_has_too_many() {
    let key = TestKey::generate();

    let parsed = JwtKeySet::parse(&key_file(&[&key, &key, &key, &key]));

    assert!(matches!(parsed, Err(JwtKeyFileError::TooManyKeys(4))));
}

#[rstest]
#[case::garbage_body(
    "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n",
    1
)]
#[case::unterminated("-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n", 1)]
fn a_block_that_is_no_rsa_public_key_is_unparsable(#[case] text: &str, #[case] position: usize) {
    let parsed = JwtKeySet::parse(text);

    assert!(
        matches!(parsed, Err(JwtKeyFileError::UnparsableKey(found)) if found == position),
        "{parsed:?}"
    );
}

#[test]
fn names_the_position_of_the_unparsable_key() {
    let key = TestKey::generate();
    let broken = "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n";
    let text = format!("{}{broken}", key.public_pem());

    assert!(matches!(
        JwtKeySet::parse(&text),
        Err(JwtKeyFileError::UnparsableKey(2))
    ));
}

#[test]
fn a_block_opened_inside_another_is_unparsable() {
    let key = TestKey::generate();
    let text = format!("-----BEGIN PUBLIC KEY-----\n{}", key.public_pem());

    assert!(matches!(
        JwtKeySet::parse(&text),
        Err(JwtKeyFileError::UnparsableKey(1))
    ));
}

#[test]
fn a_missing_file_is_unreadable() {
    let loaded = JwtKeySet::load(Path::new("/nonexistent/jwt-public-keys.pem"));

    assert!(matches!(loaded, Err(JwtKeyFileError::Unreadable(_))));
}

#[test]
fn loads_the_keys_of_a_file() {
    let key = TestKey::generate();
    let directory = scratch_dir("key-set");
    let path = directory.join("keys.pem");
    std::fs::write(&path, key.public_pem()).unwrap();

    let set = JwtKeySet::load(&path).unwrap();

    assert_eq!(set.len(), 1);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[rstest]
#[case(JwtKeyFileError::NoKey, "the key file holds no PEM key")]
#[case(
    JwtKeyFileError::TooManyKeys(5),
    "the key file holds 5 keys, but at most 3 are allowed"
)]
#[case(
    JwtKeyFileError::UnparsableKey(2),
    "key 2 of the key file is not a parsable RSA public key in PEM form"
)]
#[case(
    JwtKeyFileError::Unreadable(std::io::Error::other("gone")),
    "the key file cannot be read"
)]
fn describes_each_error(#[case] error: JwtKeyFileError, #[case] message: &str) {
    assert_eq!(error.to_string(), message);
}
