use rstest::rstest;

use super::AuditChainHead;
use crate::error::InvalidIamValue;
use crate::value_object::audit_hash::AuditHash;

#[rstest]
#[case(0)]
#[case(1)]
#[case(i64::MAX)]
fn a_head_keeps_its_sequence_and_hash(#[case] seq: i64) {
    let hash = AuditHash::new(&[7; 32]).unwrap();

    let head = AuditChainHead::new(seq, hash).unwrap();

    assert_eq!(head.seq(), seq);
    assert_eq!(head.hash(), hash);
}

#[test]
fn the_genesis_head_is_sequence_0_with_the_genesis_hash() {
    assert_eq!(AuditChainHead::GENESIS.seq(), 0);
    assert_eq!(AuditChainHead::GENESIS.hash(), AuditHash::GENESIS);
}

#[rstest]
#[case(-1)]
#[case(i64::MIN)]
fn rejects_a_negative_sequence(#[case] seq: i64) {
    assert_eq!(
        AuditChainHead::new(seq, AuditHash::GENESIS),
        Err(InvalidIamValue::AuditSequence)
    );
}
