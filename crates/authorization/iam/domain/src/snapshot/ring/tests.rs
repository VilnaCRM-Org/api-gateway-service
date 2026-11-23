use super::*;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn digest(byte: u8) -> PolicyDigestValue {
    PolicyDigestValue::from_bytes([byte; PolicyDigestValue::LENGTH])
}

#[test]
fn an_empty_ring_knows_no_version() {
    let ring = DigestRing::default();

    assert!(ring.is_empty());
    assert_eq!(ring.get(version(1)), None);
    assert_eq!(ring.newest(), None);
}

#[test]
fn it_returns_the_digest_of_each_recorded_version() {
    let mut ring = DigestRing::default();
    ring.record(version(1), digest(1));
    ring.record(version(2), digest(2));
    ring.record(version(3), digest(3));

    assert_eq!(ring.get(version(1)), Some(digest(1)));
    assert_eq!(ring.get(version(3)), Some(digest(3)));
    assert_eq!(ring.get(version(4)), None);
    assert_eq!(ring.len(), 3);
}

#[test]
fn it_forgets_the_oldest_version_beyond_its_capacity() {
    let mut ring = DigestRing::with_capacity(2);
    for value in 1..=3 {
        ring.record(version(value), digest(u8::try_from(value).unwrap()));
    }

    assert_eq!(ring.get(version(1)), None);
    assert_eq!(ring.get(version(2)), Some(digest(2)));
    assert_eq!(ring.get(version(3)), Some(digest(3)));
}

#[test]
fn it_does_not_record_a_version_that_is_not_newer() {
    let mut ring = DigestRing::default();
    ring.record(version(5), digest(5));
    ring.record(version(5), digest(9));
    ring.record(version(4), digest(4));

    assert_eq!(ring.get(version(5)), Some(digest(5)));
    assert_eq!(ring.get(version(4)), None);
}

#[test]
fn a_jump_in_versions_drops_the_digests_that_no_longer_line_up() {
    let mut ring = DigestRing::default();
    ring.record(version(1), digest(1));
    ring.record(version(10), digest(10));

    assert_eq!(ring.get(version(1)), None);
    assert_eq!(ring.get(version(10)), Some(digest(10)));
}

#[test]
fn a_ring_keeps_at_least_one_version() {
    let mut ring = DigestRing::with_capacity(0);
    ring.record(version(1), digest(1));

    assert_eq!(ring.get(version(1)), Some(digest(1)));
}
