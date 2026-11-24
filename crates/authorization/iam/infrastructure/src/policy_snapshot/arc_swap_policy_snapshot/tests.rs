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

#[test]
fn a_cell_that_is_not_deferred_drops_a_replaced_snapshot_at_once() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = ArcSwapPolicySnapshot::new();
    cell.publish(data(&clock));
    cell.publish(data(&clock));

    assert_eq!(cell.retired(), 0);
    assert_eq!(cell.reclaim(), 0);
    assert_eq!(cell.last_reclaimed_on(), None);
}

#[test]
fn a_replaced_snapshot_is_kept_until_its_last_reader_drops_it() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = ArcSwapPolicySnapshot::deferred();
    cell.publish(data(&clock));
    let held = cell.current().unwrap();
    cell.publish(data(&clock));

    assert_eq!(cell.retired(), 1);
    assert_eq!(cell.reclaim(), 0, "a request still reads it");
    assert_eq!(cell.retired(), 1);

    drop(held);

    assert_eq!(cell.reclaim(), 1);
    assert_eq!(cell.retired(), 0);
}

#[test]
fn the_destructor_of_a_retired_snapshot_runs_on_the_thread_that_reclaims() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    cell.publish(data(&clock));
    let held = cell.current().unwrap();
    cell.publish(data(&clock));
    drop(held);

    let reclaimer = {
        let cell = Arc::clone(&cell);
        std::thread::spawn(move || {
            cell.reclaim();
            std::thread::current().id()
        })
    };
    let reclaimer = reclaimer.join().unwrap();

    assert_eq!(cell.last_reclaimed_on(), Some(reclaimer));
    assert_ne!(cell.last_reclaimed_on(), Some(std::thread::current().id()));
}

#[test]
fn a_cleared_cell_shows_readers_no_snapshot_until_the_next_publication() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = ArcSwapPolicySnapshot::new();
    cell.publish(data(&clock));

    cell.clear();
    assert!(cell.current().is_none());
    assert_eq!(cell.retired(), 0);

    cell.publish(data(&clock));
    assert!(cell.current().is_some());
}

#[test]
fn a_deferred_cell_retires_the_snapshot_it_withdraws() {
    let clock = Arc::new(FakeBootClock::new());
    let cell = ArcSwapPolicySnapshot::deferred();
    cell.publish(data(&clock));
    let held = cell.current().unwrap();

    cell.clear();
    cell.clear();

    assert!(cell.current().is_none());
    assert_eq!(cell.retired(), 1);
    assert_eq!(held.version(), iam_domain::PolicyVersion::ZERO);
    drop(held);
    assert_eq!(cell.reclaim(), 1);
}
