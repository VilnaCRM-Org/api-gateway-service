use rstest::rstest;

use super::RequestDigest;
use crate::error::InvalidIamValue;

#[test]
fn a_digest_keeps_its_32_bytes() {
    let bytes: Vec<u8> = (0..32).collect();

    let digest = RequestDigest::new(&bytes).unwrap();

    assert_eq!(digest.as_bytes().as_slice(), bytes.as_slice());
}

#[rstest]
#[case(0)]
#[case(31)]
#[case(33)]
fn rejects_any_other_length(#[case] length: usize) {
    assert_eq!(
        RequestDigest::new(&vec![1; length]),
        Err(InvalidIamValue::RequestDigestLength)
    );
}
