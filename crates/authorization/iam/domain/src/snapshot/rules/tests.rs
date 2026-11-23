use super::*;
use crate::state::key::StateKey;
use crate::value_object::policy_digest_value::PolicyDigestValue;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn digest(byte: u8) -> PolicyDigestValue {
    PolicyDigestValue::from_bytes([byte; PolicyDigestValue::LENGTH])
}

fn record(
    version_number: i64,
    log_epoch: i64,
    relay_epoch: i64,
    digest_after: u8,
) -> VersionedRecord {
    VersionedRecord {
        key: StateKey::Head,
        payload: None,
        version: version(version_number),
        seq: 1,
        count: 1,
        digest_after: digest(digest_after),
        log_epoch: LogEpoch::new(log_epoch).unwrap(),
        relay_epoch: RelayEpoch::new(relay_epoch).unwrap(),
    }
}

fn position(applied: i64) -> ApplyPosition {
    ApplyPosition {
        applied: version(applied),
        log_epoch: LogEpoch::new(2).unwrap(),
        relay_epoch: RelayEpoch::new(3).unwrap(),
    }
}

fn ring() -> DigestRing {
    let mut ring = DigestRing::default();
    ring.record(version(4), digest(4));
    ring.record(version(5), digest(5));
    ring
}

#[test]
fn the_next_version_proceeds() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(6, 2, 3, 6)),
        RecordVerdict::Next
    );
}

#[test]
fn a_later_version_is_a_gap_that_names_the_expected_version() {
    let verdict = ApplyRules::judge(&position(5), &ring(), &record(7, 2, 3, 7));

    assert_eq!(
        verdict,
        RecordVerdict::Gap {
            expected: version(6)
        }
    );
    assert!(!verdict.is_fence());
}

#[test]
fn an_applied_version_with_the_same_digest_is_ignored() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(5, 2, 3, 5)),
        RecordVerdict::AlreadyApplied
    );
}

#[test]
fn an_applied_version_with_another_digest_is_conflicting_content() {
    let verdict = ApplyRules::judge(&position(5), &ring(), &record(5, 2, 3, 99));

    assert_eq!(
        verdict,
        RecordVerdict::Fence(FenceVerdict::ConflictingContent)
    );
    assert!(verdict.is_fence());
}

#[test]
fn a_lower_log_epoch_fences() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(5, 1, 3, 5)),
        RecordVerdict::Fence(FenceVerdict::LowerLogEpoch)
    );
}

#[test]
fn a_lower_relay_epoch_is_ignored() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(6, 2, 2, 6)),
        RecordVerdict::LowerRelayEpoch
    );
}

#[test]
fn an_applied_version_older_than_the_ring_is_ignored() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(1, 2, 3, 1)),
        RecordVerdict::BeyondRing
    );
}

#[test]
fn an_inner_record_of_an_applied_version_is_ignored() {
    let mut inner = record(5, 2, 3, 99);
    inner.seq = 1;
    inner.count = 2;

    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &inner),
        RecordVerdict::AlreadyApplied
    );
}

#[test]
fn a_higher_epoch_than_the_followed_one_proceeds() {
    assert_eq!(
        ApplyRules::judge(&position(5), &ring(), &record(6, 3, 4, 6)),
        RecordVerdict::Next
    );
}

#[test]
fn the_version_guard_admits_only_a_higher_version() {
    assert!(ApplyRules::admits(None, version(1)));
    assert!(ApplyRules::admits(Some(version(1)), version(2)));
    assert!(!ApplyRules::admits(Some(version(2)), version(2)));
    assert!(!ApplyRules::admits(Some(version(3)), version(2)));
}

#[test]
fn no_version_follows_the_highest_representable_one() {
    assert_eq!(
        ApplyRules::judge(&position(i64::MAX), &ring(), &record(i64::MAX, 2, 3, 9)),
        RecordVerdict::BeyondRing
    );
}
