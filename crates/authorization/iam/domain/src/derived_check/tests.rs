use super::*;

#[test]
fn a_shard_belongs_to_the_group_of_its_remainder() {
    assert!(in_group(0, 0));
    assert!(in_group(17, 1));
    assert!(in_group(4_095, 15));
    assert!(!in_group(17, 0));
    assert!(!in_group(16, 1));
}

#[test]
fn every_shard_belongs_to_exactly_one_group() {
    for shard in 0..4_096 {
        let groups = (0..CHECK_GROUPS)
            .filter(|group| in_group(shard, *group))
            .count();

        assert_eq!(groups, 1, "shard {shard}");
    }
}

#[test]
fn a_mismatch_names_its_shard() {
    let mismatch = DerivedMismatch {
        shard: 42,
        rebuilt: PolicyDigestValue::ZERO,
        held: PolicyDigestValue::from_bytes([1; PolicyDigestValue::LENGTH]),
    };

    assert_eq!(
        mismatch.to_string(),
        "the derived structures of shard 42 do not match the raw records"
    );
}
