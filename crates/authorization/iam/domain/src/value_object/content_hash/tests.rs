use rstest::rstest;

use super::ContentHash;
use crate::value_object::request_digest::RequestDigest;

#[test]
fn a_hash_keeps_its_32_bytes_and_renders_as_lower_case_hex() {
    let bytes: Vec<u8> = (0..32).map(|byte| byte * 8).collect();

    let hash = ContentHash::new(&bytes).unwrap();

    assert_eq!(hash.as_bytes().as_slice(), bytes.as_slice());
    assert_eq!(
        hash.to_string(),
        "0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f8"
    );
}

#[rstest]
#[case(0)]
#[case(31)]
#[case(33)]
fn rejects_any_other_length(#[case] length: usize) {
    assert_eq!(ContentHash::new(&vec![1; length]), None);
}

#[test]
fn hashes_compare_by_their_bytes() {
    assert_eq!(ContentHash::new(&[7; 32]), ContentHash::new(&[7; 32]));
    assert_ne!(ContentHash::new(&[7; 32]), ContentHash::new(&[8; 32]));
}

#[test]
fn a_request_digest_becomes_the_hash_with_the_same_bytes() {
    let hash = ContentHash::from(RequestDigest::from_bytes([9; 32]));

    assert_eq!(hash, ContentHash::new(&[9; 32]).unwrap());
}
