use std::collections::HashSet;

use super::CredentialDigest;

fn digest() -> CredentialDigest {
    let mut bytes = [0_u8; CredentialDigest::LENGTH];
    for (byte, value) in bytes.iter_mut().zip(0_u8..) {
        *byte = value.wrapping_mul(17).wrapping_add(10);
    }
    CredentialDigest::new(bytes)
}

#[test]
fn the_prefix_is_the_first_four_bytes_in_lower_case_hexadecimal() {
    assert_eq!(digest().prefix(), "0a1b2c3d");
}

#[test]
fn debug_prints_only_the_eight_character_prefix() {
    let printed = format!("{:?}", digest());

    assert_eq!(printed, "CredentialDigest(0a1b2c3d…)");
    assert!(!printed.contains("4e"), "{printed}");
}

#[test]
fn the_bytes_are_kept() {
    assert_eq!(digest().as_bytes().len(), 32);
    assert_eq!(
        digest().as_bytes().get(31),
        Some(&31_u8.wrapping_mul(17).wrapping_add(10))
    );
}

#[test]
fn equal_bytes_give_equal_digests_and_keys() {
    let set: HashSet<CredentialDigest> = [digest(), digest(), CredentialDigest::new([0; 32])]
        .into_iter()
        .collect();

    assert_eq!(set.len(), 2);
    assert_ne!(digest(), CredentialDigest::new([0; 32]));
}
