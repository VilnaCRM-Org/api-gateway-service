use iam_domain::{PolicyDigest as _, StateKey};

use super::Sha256PolicyDigest;

#[test]
fn an_entity_hash_is_16_bytes_and_repeatable() {
    let hash = Sha256PolicyDigest.entity_hash(&StateKey::Head, "{}");

    assert_eq!(hash.to_hex().len(), 32);
    assert_eq!(hash, Sha256PolicyDigest.entity_hash(&StateKey::Head, "{}"));
}

#[test]
fn the_key_and_the_state_both_change_the_hash() {
    let base = Sha256PolicyDigest.entity_hash(&StateKey::Head, "{}");

    assert_ne!(base, Sha256PolicyDigest.entity_hash(&StateKey::Head, "[]"));
    assert_ne!(
        base,
        Sha256PolicyDigest.entity_hash(&StateKey::GlobalRevocation, "{}")
    );
}

#[test]
fn the_hash_of_known_input_matches_the_sha256_vector() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223 b00361a396177a9cb410ff61f20015ad; the
    // content address of the text "abc" is its first 16 bytes.
    let id = Sha256PolicyDigest.content_id("abc");

    assert_eq!(id.as_str(), "ba7816bf8f01cfea414140de5dae2223");
}

#[test]
fn the_entity_hash_hashes_the_printed_key_followed_by_the_state() {
    // The key `__head` followed by the state `abc` hashes as the text "__headabc".
    let joined = Sha256PolicyDigest.content_id("__headabc");
    let hash = Sha256PolicyDigest.entity_hash(&StateKey::Head, "abc");

    assert_eq!(hash.to_hex(), joined.as_str());
}
