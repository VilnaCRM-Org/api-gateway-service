use super::DocumentLimits;

#[test]
fn the_decision_api_limits_are_the_documented_ones() {
    let limits = DocumentLimits::decision_api();

    assert_eq!(limits.bytes, 65_536);
    assert_eq!(limits.depth, 15);
    assert_eq!(limits.coordinates, 500);
    assert_eq!(limits.aliases, 50);
    assert_eq!(limits.fragments, 100);
    assert_eq!(limits, DocumentLimits::default());
}

#[test]
fn another_byte_limit_keeps_the_other_limits() {
    let limits = DocumentLimits::decision_api().with_bytes(10);

    assert_eq!(limits.bytes, 10);
    assert_eq!(limits.depth, 15);
    assert_eq!(limits.fragments, 100);
}
