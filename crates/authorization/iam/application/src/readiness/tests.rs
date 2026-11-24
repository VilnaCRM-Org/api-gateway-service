use std::sync::Arc;
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock as _, BootInstant, FreshnessRule, PolicyVersion};
use test_support::boot_clock::FakeBootClock;
use test_support::policy_view::{EmptySnapshot, FakePolicyView};

use super::{LIVENESS_LIMIT, NotReady, NotStarted, PodProbes, PodStatus};
use crate::freshness::FreshnessState;

const HARD: Duration = Duration::from_secs(15);
const READY: Duration = Duration::from_secs(2);

struct Pod {
    probes: PodProbes,
    status: Arc<PodStatus>,
    state: Arc<FreshnessState>,
    clock: Arc<FakeBootClock>,
}

fn pod_with(view: FakePolicyView) -> Pod {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD, READY),
        Arc::<FakeBootClock>::clone(&clock),
    ));
    let status = Arc::new(PodStatus::new());
    let probes = PodProbes::new(Arc::clone(&status), Arc::clone(&state), Arc::new(view));
    Pod {
        probes,
        status,
        state,
        clock,
    }
}

fn published() -> FakePolicyView {
    FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(PolicyVersion::new(3).unwrap())))
}

fn prove(pod: &Pod) {
    pod.state.attach(
        FreshnessProof {
            taken_at: pod.clock.now(),
            watermark: 5,
        },
        PolicyVersion::new(3).unwrap(),
    );
}

/// A pod whose bootstrap finished, whose gates passed and whose key set is parsed.
fn bootstrapped() -> Pod {
    let pod = pod_with(published());
    pod.status.mark_keys_parsed();
    pod.status.mark_config_gates_passed();
    pod.status.mark_bootstrapped();
    pod
}

#[test]
fn a_pod_before_its_bootstrap_is_not_started_and_not_ready() {
    let pod = pod_with(FakePolicyView::failing());

    assert_eq!(pod.probes.startup(), Err(NotStarted::KeysNotParsed));
    assert_eq!(
        pod.probes.ready(),
        Err(NotReady::NotStarted(NotStarted::KeysNotParsed))
    );
}

#[test]
fn startup_names_the_first_condition_that_does_not_hold() {
    let pod = pod_with(published());
    pod.status.mark_keys_parsed();
    assert_eq!(pod.probes.startup(), Err(NotStarted::ConfigGatesPending));

    pod.status.mark_config_gates_passed();
    assert_eq!(pod.probes.startup(), Err(NotStarted::NotBootstrapped));

    pod.status.mark_bootstrapped();
    assert_eq!(pod.probes.startup(), Err(NotStarted::NoProofAttached));

    prove(&pod);
    assert_eq!(pod.probes.startup(), Ok(()));
}

#[test]
fn a_bootstrap_without_a_published_snapshot_is_not_a_started_pod() {
    let pod = pod_with(FakePolicyView::failing());
    pod.status.mark_keys_parsed();
    pod.status.mark_config_gates_passed();
    pod.status.mark_bootstrapped();
    prove(&pod);

    assert_eq!(pod.probes.startup(), Err(NotStarted::NotBootstrapped));
}

#[test]
fn a_completed_bootstrap_with_a_proof_is_started_and_ready() {
    let pod = bootstrapped();
    prove(&pod);

    assert_eq!(pod.probes.startup(), Ok(()));
    assert_eq!(pod.probes.ready(), Ok(()));
}

#[test]
fn a_fenced_pod_is_not_ready_until_the_rebootstrap_completes_and_stays_started() {
    let pod = bootstrapped();
    prove(&pod);
    assert_eq!(pod.probes.ready(), Ok(()));

    pod.status.begin_rebootstrap();
    assert_eq!(pod.probes.startup(), Ok(()));
    assert_eq!(pod.probes.ready(), Err(NotReady::Rebootstrapping));

    pod.status.end_rebootstrap();
    assert_eq!(pod.probes.ready(), Ok(()));
}

#[test]
fn a_withdrawn_snapshot_makes_the_pod_not_ready_but_not_unstarted() {
    let started = bootstrapped();
    prove(&started);
    assert_eq!(started.probes.startup(), Ok(()));

    // The derived-state check withdrew the snapshot: the same status, a view without a snapshot.
    let withdrawn = PodProbes::new(
        Arc::clone(&started.status),
        Arc::clone(&started.state),
        Arc::new(FakePolicyView::failing()),
    );

    assert_eq!(withdrawn.startup(), Ok(()));
    assert_eq!(withdrawn.ready(), Err(NotReady::NoSnapshot));
}

#[test]
fn a_proof_older_than_the_ready_bound_makes_the_pod_not_ready_and_a_newer_one_ready_again() {
    let pod = bootstrapped();
    prove(&pod);
    assert_eq!(pod.probes.ready(), Ok(()));

    pod.clock.advance(READY);
    assert_eq!(pod.probes.ready(), Ok(()));

    pod.clock.advance(Duration::from_millis(1));
    assert_eq!(pod.probes.ready(), Err(NotReady::ProofAged));
    assert_eq!(pod.probes.startup(), Ok(()));

    prove(&pod);
    assert_eq!(pod.probes.ready(), Ok(()));
}

#[test]
fn a_stale_verdict_makes_the_pod_not_ready() {
    let pod = bootstrapped();
    prove(&pod);
    assert_eq!(pod.probes.startup(), Ok(()));

    pod.clock.advance(HARD + Duration::from_secs(1));

    assert_eq!(pod.probes.ready(), Err(NotReady::NotFresh));
}

#[test]
fn a_withdrawn_proof_makes_the_pod_not_ready() {
    let pod = bootstrapped();
    prove(&pod);
    assert_eq!(pod.probes.startup(), Ok(()));

    pod.state.invalidate();

    assert_eq!(pod.probes.ready(), Err(NotReady::NotFresh));
}

#[test]
fn liveness_holds_until_the_watchdog_is_ten_seconds_old() {
    let pod = pod_with(FakePolicyView::failing());
    assert!(pod.probes.live());

    pod.state.tick();
    pod.clock.advance(Duration::from_millis(9999));
    assert!(pod.probes.live());

    pod.clock.advance(Duration::from_millis(1));
    assert!(!pod.probes.live());

    pod.state.tick();
    assert!(pod.probes.live());
}

#[test]
fn liveness_counts_from_the_creation_of_the_state_until_the_first_tick() {
    let pod = pod_with(FakePolicyView::failing());

    pod.clock.advance(LIVENESS_LIMIT);

    assert!(!pod.probes.live());
}

#[test]
fn liveness_never_reads_the_status_flags() {
    let pod = pod_with(FakePolicyView::failing());
    pod.status.begin_rebootstrap();

    assert!(pod.probes.live());
}

#[test]
fn the_reasons_are_readable() {
    assert_eq!(
        NotStarted::KeysNotParsed.to_string(),
        "the JWT key set is not parsed"
    );
    assert_eq!(
        NotReady::Rebootstrapping.to_string(),
        "the pod is rebootstrapping"
    );
    assert_eq!(
        NotReady::NotStarted(NotStarted::NoProofAttached).to_string(),
        "the pod is not started: no freshness proof is attached to the published snapshot"
    );
}

#[test]
fn the_status_records_each_fact_on_its_own() {
    let status = PodStatus::new();
    assert!(!status.are_keys_parsed());
    assert!(!status.are_config_gates_passed());
    assert!(!status.is_bootstrapped());
    assert!(!status.is_rebootstrapping());

    status.mark_keys_parsed();
    assert!(status.are_keys_parsed());
    assert!(!status.are_config_gates_passed());

    status.mark_config_gates_passed();
    status.mark_bootstrapped();
    status.begin_rebootstrap();
    assert!(status.are_config_gates_passed());
    assert!(status.is_bootstrapped());
    assert!(status.is_rebootstrapping());

    status.end_rebootstrap();
    assert!(!status.is_rebootstrapping());
}
