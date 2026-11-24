use std::sync::Arc;
use std::time::Duration;

use iam_application::FreshnessState;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootInstant, FreshnessRule, LogEpoch, PolicyDigestValue, PolicyVersion};
use iam_infrastructure::{
    ApplyOutcome, ArcSwapPolicySnapshot, JsonStateRecordCodec, MatchitRouteTableCompiler,
    PUBLISH_INTERVAL, PolicySnapshotBuilder, Sha256PolicyDigest, SnapshotPorts,
};
use test_support::boot_clock::FakeBootClock;

use super::Proofs;

/// A builder that applied the empty state at `number` and published it to `cell`.
fn publishing(cell: &Arc<ArcSwapPolicySnapshot>, number: i64) -> PolicySnapshotBuilder {
    let ports = SnapshotPorts {
        codec: Arc::new(JsonStateRecordCodec),
        digest: Arc::new(Sha256PolicyDigest),
        compiler: Arc::new(MatchitRouteTableCompiler),
        boot_clock: Arc::new(FakeBootClock::new()),
    };
    let mut builder = PolicySnapshotBuilder::new(ports, Arc::clone(cell), PUBLISH_INTERVAL);
    builder
        .rebuild_verified(
            &[],
            PolicyVersion::new(number).unwrap(),
            (LogEpoch::ZERO, PolicyDigestValue::ZERO),
        )
        .unwrap();
    builder
}

fn fresh_state() -> Arc<FreshnessState> {
    Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::new(FakeBootClock::new()),
    ))
}

fn proof(watermark: i64) -> FreshnessProof {
    FreshnessProof {
        taken_at: BootInstant::from_elapsed(Duration::from_secs(1)),
        watermark,
    }
}

#[test]
fn without_a_freshness_state_proofs_are_dropped() {
    let mut proofs = Proofs::new(None);

    proofs.offer(proof(1));

    assert_eq!(proofs.attachment.waiting(), 0);
}

#[test]
fn the_outcomes_of_the_builder_move_the_cover() {
    let mut proofs = Proofs::new(Some(fresh_state()));
    proofs.installed(0);
    proofs.offer(proof(3));

    proofs.record(0, &ApplyOutcome::Pending { missing: Some(1) });
    assert_eq!(proofs.attachment.take_attachable(), None);

    proofs.record(
        1,
        &ApplyOutcome::Applied {
            version: PolicyVersion::new(1).unwrap(),
            published: false,
        },
    );
    proofs.record(2, &ApplyOutcome::Duplicate);
    proofs.caught_up(3, 3);

    assert_eq!(proofs.attachment.take_attachable(), Some(proof(3)));
}

#[test]
fn a_proof_is_attached_to_the_snapshot_the_builder_applied() {
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let builder = publishing(&cell, 3);
    let state = fresh_state();
    let mut proofs = Proofs::new(Some(Arc::clone(&state)));
    proofs.installed(3);
    proofs.offer(proof(3));

    proofs.attach(&builder, &cell);

    assert!(state.is_fresh());
}

#[test]
fn a_snapshot_that_lags_the_builder_gets_no_proof() {
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let other = Arc::new(ArcSwapPolicySnapshot::deferred());
    publishing(&cell, 3);
    let ahead = publishing(&other, 4);
    let state = fresh_state();
    let mut proofs = Proofs::new(Some(Arc::clone(&state)));
    proofs.installed(3);
    proofs.offer(proof(3));

    proofs.attach(&ahead, &cell);

    assert!(!state.is_fresh());
}

#[test]
fn without_a_freshness_state_nothing_is_attached() {
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let builder = publishing(&cell, 3);
    let mut proofs = Proofs::new(None);
    proofs.offer(proof(3));

    proofs.attach(&builder, &cell);

    assert_eq!(proofs.attachment.waiting(), 0);
}

#[test]
fn before_a_snapshot_is_published_nothing_is_attached() {
    let other = Arc::new(ArcSwapPolicySnapshot::deferred());
    let builder = publishing(&other, 3);
    let unpublished = Arc::new(ArcSwapPolicySnapshot::deferred());
    let state = fresh_state();
    let mut proofs = Proofs::new(Some(Arc::clone(&state)));
    proofs.installed(3);
    proofs.offer(proof(3));

    proofs.attach(&builder, &unpublished);

    assert!(!state.is_fresh());
    assert_eq!(proofs.attachment.waiting(), 1);
}
