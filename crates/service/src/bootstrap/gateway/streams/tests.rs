use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock as _, BootInstant, FreshnessRule, HttpMethod, PolicyVersion};
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};

use super::*;

const HARD_BOUND: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
struct Fence(AtomicBool);

impl StreamFence for Fence {
    fn closed(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn streams() -> Arc<Streams> {
    Streams::new(
        StreamSettings {
            idle_timeout: Duration::from_mins(5),
            per_subject: 2,
        },
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    )
}

fn open(streams: &Streams, subject: &str) -> Result<StreamHandle, SubjectAtCap> {
    let record = StreamRecord {
        subject: Some(subject.to_owned()),
        session: None,
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 1,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/events".to_owned(),
    };
    streams.registry().open(record, grant)
}

fn freshness(boot: &Arc<FakeBootClock>) -> Arc<FreshnessState> {
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD_BOUND, Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(boot),
    ));
    state.attach(
        FreshnessProof {
            taken_at: boot.now(),
            watermark: 1,
        },
        PolicyVersion::new(7).unwrap(),
    );
    state
}

fn boot() -> Arc<FakeBootClock> {
    Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )))
}

fn serving() -> Arc<dyn PolicyView> {
    Arc::new(CountingPolicyView::serving(GatewaySnapshot::at(
        PolicyVersion::new(7).unwrap(),
    )))
}

#[test]
fn the_settings_name_the_idle_timeout_and_the_subject_cap() {
    let streams = streams();

    let first = open(&streams, "user-1").unwrap();
    let second = open(&streams, "user-1").unwrap();

    assert!(open(&streams, "user-1").is_err());
    assert!(open(&streams, "user-2").is_ok());
    drop((first, second));
}

#[test]
fn the_streams_hand_out_their_clock_and_their_registry() {
    let streams = streams();

    assert_eq!(streams.now(), SystemTime::UNIX_EPOCH);
    assert_eq!(streams.clock().now(), SystemTime::UNIX_EPOCH);
    assert!(streams.registry().is_empty());
}

#[test]
fn a_fresh_pod_with_a_snapshot_keeps_its_streams() {
    let boot = boot();
    let fence = PodFence::new(serving(), freshness(&boot));

    assert!(!fence.closed());
}

#[test]
fn a_pod_without_a_snapshot_has_fenced() {
    let boot = boot();
    let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::empty());
    let fence = PodFence::new(view, freshness(&boot));

    assert!(fence.closed());
}

#[test]
fn a_pod_whose_proof_outlived_the_hard_bound_may_not_serve() {
    let boot = boot();
    let fence = PodFence::new(serving(), freshness(&boot));

    boot.advance(HARD_BOUND.saturating_add(Duration::from_secs(1)));

    assert!(fence.closed());
}

#[tokio::test(start_paused = true)]
async fn the_watch_scans_on_every_tick_and_stops_with_the_flag() {
    let streams = streams();
    let held = open(&streams, "user-1").unwrap();
    let fence = Arc::new(Fence::default());
    let (stop, stopping) = watch::channel(false);
    let watching = tokio::spawn(Arc::clone(&streams).watch(Arc::<Fence>::clone(&fence), stopping));

    tokio::time::sleep(SCAN_INTERVAL.saturating_mul(3)).await;
    assert_eq!(streams.registry().len(), 1);
    fence.0.store(true, Ordering::SeqCst);
    tokio::time::sleep(SCAN_INTERVAL.saturating_mul(2)).await;

    assert_eq!(held.closed().await, CloseReason::Fenced);
    stop.send_replace(true);
    watching.await.unwrap();
}

#[test]
fn the_number_of_open_streams_is_reported_only_when_it_changes() {
    let streams = streams();
    let held = open(&streams, "user-1").unwrap();

    assert_eq!(streams.report(0), 1);
    assert_eq!(streams.report(1), 1);
    drop(held);
    assert_eq!(streams.report(1), 0);
}
