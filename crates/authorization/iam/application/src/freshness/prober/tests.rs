use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock as _, BootInstant, FreshnessRule, PolicyVersion, ProbeError};
use test_support::boot_clock::FakeBootClock;
use test_support::log::LogRecorder;
use test_support::peer_freshness_client::FakePeerFreshnessClient;
use test_support::policy_log_probe::FakePolicyLogProbe;
use test_support::policy_view::{EmptySnapshot, FakePolicyView};

use super::{FreshnessProber, ProberPorts, ProberSettings, ProofSink};
use crate::freshness::state::FreshnessState;
use tokio::sync::watch;

const HARD: Duration = Duration::from_secs(15);
const READY: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
struct RecordingSink(Mutex<Vec<FreshnessProof>>);

impl ProofSink for RecordingSink {
    fn offer(&self, proof: FreshnessProof) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(proof);
    }
}

struct Rig {
    prober: FreshnessProber,
    clock: Arc<FakeBootClock>,
    sink: Arc<RecordingSink>,
    state: Arc<FreshnessState>,
    peers: Arc<FakePeerFreshnessClient>,
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn rig(results: Vec<Result<FreshnessProof, ProbeError>>, view: FakePolicyView) -> Rig {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD, READY),
        Arc::<FakeBootClock>::clone(&clock),
    ));
    let sink = Arc::new(RecordingSink::default());
    let peers = Arc::new(FakePeerFreshnessClient::new());
    let prober = FreshnessProber::new(
        ProberPorts {
            probe: Arc::new(FakePolicyLogProbe::scripted(results)),
            peers: Arc::<FakePeerFreshnessClient>::clone(&peers),
            view: Arc::new(view),
            clock: Arc::<FakeBootClock>::clone(&clock),
            sink: Arc::<RecordingSink>::clone(&sink),
            state: Arc::<FreshnessState>::clone(&state),
        },
        ProberSettings {
            probe_interval: Duration::from_secs(1),
        },
    );
    Rig {
        prober,
        clock,
        sink,
        state,
        peers,
    }
}

fn view_at(value: i64) -> FakePolicyView {
    FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(version(value))))
}

fn proof(clock: &FakeBootClock, watermark: i64) -> FreshnessProof {
    FreshnessProof {
        taken_at: clock.now(),
        watermark,
    }
}

fn recorded(sink: &RecordingSink) -> Vec<FreshnessProof> {
    sink.0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[tokio::test]
async fn a_proof_of_the_probe_goes_to_the_sink() {
    let clock = FakeBootClock::new();
    let wanted = proof(&clock, 9);
    let rig = rig(vec![Ok(wanted)], view_at(1));

    rig.prober.probe_once().await;

    assert_eq!(recorded(&rig.sink), vec![wanted]);
}

#[tokio::test]
async fn a_failed_probe_produces_no_proof() {
    let rig = rig(vec![Err(ProbeError::FencedLeaderEpoch)], view_at(1));

    rig.prober.probe_once().await;

    assert_eq!(recorded(&rig.sink).len(), 0);
}

#[tokio::test]
async fn a_jump_of_the_boot_clock_beyond_the_ready_bound_makes_the_next_tick_invalidate_the_proof()
{
    let rig = rig(vec![], view_at(1));
    rig.prober.watchdog_tick();
    rig.state.attach(proof(&rig.clock, 3), version(1));
    rig.prober.watchdog_tick();
    assert!(rig.state.is_fresh());

    rig.clock.jump(READY + Duration::from_millis(1));
    rig.prober.watchdog_tick();

    assert!(!rig.state.is_fresh());
}

#[tokio::test]
async fn a_peer_ahead_for_one_and_a_half_seconds_invalidates_the_proof() {
    let rig = rig(vec![], view_at(5));
    rig.state.attach(proof(&rig.clock, 3), version(5));
    rig.peers.report(vec![version(6)]);

    for _ in 0..5 {
        rig.prober.check_peers().await;
        rig.clock.advance(Duration::from_millis(250));
    }
    assert!(rig.state.is_fresh());

    rig.prober.check_peers().await;

    assert!(!rig.state.is_fresh());
}

#[tokio::test]
async fn a_peer_ahead_for_half_a_second_does_not() {
    let rig = rig(vec![], view_at(5));
    rig.state.attach(proof(&rig.clock, 3), version(5));
    rig.peers.report(vec![version(6)]);

    for _ in 0..3 {
        rig.prober.check_peers().await;
        rig.clock.advance(Duration::from_millis(250));
    }
    rig.peers.report(vec![version(5)]);
    for _ in 0..10 {
        rig.prober.check_peers().await;
        rig.clock.advance(Duration::from_millis(250));
    }

    assert!(rig.state.is_fresh());
}

#[tokio::test]
async fn a_pod_that_is_not_fresh_is_not_cross_checked() {
    let rig = rig(vec![], view_at(5));
    rig.peers.report(vec![version(9)]);

    rig.clock.advance(Duration::from_secs(5));
    rig.prober.check_peers().await;
    rig.state.attach(proof(&rig.clock, 3), version(5));
    rig.prober.check_peers().await;

    assert!(rig.state.is_fresh());
}

#[tokio::test]
async fn an_empty_peer_set_leaves_the_proof_alone() {
    let rig = rig(vec![], view_at(5));
    rig.state.attach(proof(&rig.clock, 3), version(5));

    for _ in 0..8 {
        rig.prober.check_peers().await;
        rig.clock.advance(Duration::from_millis(250));
    }

    assert!(rig.state.is_fresh());
}

#[tokio::test(start_paused = true)]
async fn the_loops_probe_every_interval_and_stop_with_the_flag() {
    let clock = FakeBootClock::new();
    let results = (0..10).map(|_| Ok(proof(&clock, 1))).collect();
    let rig = rig(results, view_at(1));
    let sink = Arc::<RecordingSink>::clone(&rig.sink);
    let (stop, stopping) = watch::channel(false);
    let task = tokio::spawn(rig.prober.run(stopping));

    tokio::time::sleep(Duration::from_millis(2_500)).await;
    stop.send_replace(true);
    task.await.unwrap();

    assert_eq!(recorded(&sink).len(), 3);
}

#[tokio::test]
async fn the_watchdog_reports_why_the_pod_is_fresh_or_stale() {
    let (recorder, _guard) = LogRecorder::install();
    let rig = rig(vec![], view_at(1));

    rig.prober.watchdog_tick();
    rig.state.attach(proof(&rig.clock, 3), version(1));
    rig.prober.watchdog_tick();
    for _ in 0..16 {
        rig.clock.advance(Duration::from_secs(1));
        rig.prober.watchdog_tick();
    }
    rig.state.attach(proof(&rig.clock, 4), version(1));
    rig.clock.jump(READY + Duration::from_millis(1));
    rig.prober.watchdog_tick();

    let mut reasons: Vec<String> = recorder
        .lines()
        .iter()
        .filter(|line| line.field("metric") == Some("policy_fresh"))
        .filter_map(|line| line.field("reason").map(str::to_owned))
        .collect();
    reasons.dedup();
    assert_eq!(reasons, ["no_proof", "fresh", "aged", "gap"]);
}
