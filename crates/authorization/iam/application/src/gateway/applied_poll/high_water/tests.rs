use std::sync::Arc;
use std::time::Duration;

use iam_domain::PolicyBootstrapLog as _;
use test_support::policy_bootstrap_log::FakePolicyBootstrapLog;

use super::{BootstrapHighWater, RecordingBootstrapLog};

#[test]
fn nothing_is_covered_before_a_capture() {
    let high_water = BootstrapHighWater::new();

    assert!(!high_water.covers(0));
}

#[test]
fn an_offset_below_the_captured_end_is_covered_and_the_end_itself_is_not() {
    let high_water = BootstrapHighWater::new();

    high_water.capture(10);

    assert!(high_water.covers(0));
    assert!(high_water.covers(9));
    assert!(!high_water.covers(10));
    assert!(!high_water.covers(11));
}

#[test]
fn a_lower_capture_never_lowers_the_record() {
    let high_water = BootstrapHighWater::new();
    high_water.capture(10);

    high_water.capture(4);

    assert!(high_water.covers(9));
}

#[tokio::test(start_paused = true)]
async fn a_waiter_wakes_when_a_capture_reaches_beyond_its_offset() {
    let high_water = Arc::new(BootstrapHighWater::new());
    let waiting = tokio::spawn({
        let high_water = Arc::clone(&high_water);
        async move { high_water.covered(7).await }
    });
    high_water.capture(7);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!waiting.is_finished());

    high_water.capture(8);

    waiting.await.unwrap();
}

#[tokio::test]
async fn the_recording_log_notes_the_end_every_capture_returns() {
    let high_water = Arc::new(BootstrapHighWater::new());
    let inner = Arc::new(FakePolicyBootstrapLog::scripted(Vec::new(), &[5, 9]));
    let log = RecordingBootstrapLog::new(
        Arc::<FakePolicyBootstrapLog>::clone(&inner),
        Arc::clone(&high_water),
    );

    assert_eq!(log.stable_end().await.unwrap(), 5);
    assert!(high_water.covers(4));
    assert!(!high_water.covers(5));
    assert_eq!(log.stable_end().await.unwrap(), 9);
    assert!(high_water.covers(8));
    assert_eq!(inner.captures(), 2);
}

#[tokio::test]
async fn a_failed_capture_notes_nothing_and_the_other_calls_pass_through() {
    let high_water = Arc::new(BootstrapHighWater::new());
    let inner = Arc::new(FakePolicyBootstrapLog::with(Vec::new()).unavailable());
    let log = RecordingBootstrapLog::new(
        Arc::<FakePolicyBootstrapLog>::clone(&inner),
        Arc::clone(&high_water),
    );

    assert!(log.stable_end().await.is_err());
    assert!(log.read_framed(0, 5).await.is_err());
    log.close().await;

    assert!(!high_water.covers(0));
    assert_eq!(inner.reads(), 1);
    assert_eq!(inner.closes(), 1);
}

#[test]
fn a_default_record_has_captured_nothing() {
    let high_water = BootstrapHighWater::default();

    assert!(!high_water.covers(0));
}
