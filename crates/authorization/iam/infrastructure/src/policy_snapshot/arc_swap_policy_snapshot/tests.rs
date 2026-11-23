use std::sync::Arc;

use iam_domain::PolicyDigestValue;
use test_support::boot_clock::FakeBootClock;

use super::*;
use crate::policy_snapshot::working::Working;

fn data(published: &Arc<FakeBootClock>) -> Arc<SnapshotData> {
    Arc::new(SnapshotData::new(
        Working::empty(iam_domain::LogEpoch::ZERO),
        iam_domain::BootClock::now(published.as_ref()),
    ))
}

#[test]
fn nothing_is_current_before_the_first_publication() {
    let cell = ArcSwapPolicySnapshot::new();

    assert!(cell.current().is_none());
    assert!(cell.load().is_none());
}

#[test]
fn a_reader_keeps_the_snapshot_it_took_while_a_newer_one_is_published() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = ArcSwapPolicySnapshot::new();
    cell.publish(data(&clock));
    let held = cell.current().unwrap();

    cell.publish(data(&clock));
    let latest = cell.current().unwrap();

    assert!(!Arc::ptr_eq(&held, &latest));
    assert_eq!(held.digest(), PolicyDigestValue::ZERO);
    assert_eq!(held.version(), iam_domain::PolicyVersion::ZERO);
    assert_eq!(held.freshness_proof().version, held.version());
}
