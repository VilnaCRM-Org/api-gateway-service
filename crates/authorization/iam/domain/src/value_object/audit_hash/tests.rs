use rstest::rstest;

use super::AuditHash;
use crate::error::InvalidIamValue;

#[test]
fn a_hash_keeps_its_32_bytes_and_renders_as_lower_case_hex() {
    let bytes: Vec<u8> = (0..32).map(|byte| byte * 8).collect();

    let hash = AuditHash::new(&bytes).unwrap();

    assert_eq!(hash.as_bytes().as_slice(), bytes.as_slice());
    assert_eq!(
        hash.to_string(),
        "0008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f8"
    );
}

#[test]
fn the_genesis_hash_is_32_zero_bytes() {
    assert_eq!(AuditHash::GENESIS.as_bytes(), &[0; 32]);
    assert_eq!(AuditHash::GENESIS.to_string(), "0".repeat(64));
}

#[rstest]
#[case(0)]
#[case(31)]
#[case(33)]
fn rejects_any_other_length(#[case] length: usize) {
    assert_eq!(
        AuditHash::new(&vec![1; length]),
        Err(InvalidIamValue::AuditHashLength)
    );
}
