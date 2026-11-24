use std::time::Duration;

use super::{Freshness, FreshnessRule, StaleCause};
use crate::freshness::proof::FreshnessProof;
use crate::value_object::boot_instant::BootInstant;

const HARD: Duration = Duration::from_secs(15);
const READY: Duration = Duration::from_secs(2);

fn rule() -> FreshnessRule {
    FreshnessRule::new(HARD, READY)
}

fn at(millis: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_millis(millis))
}

fn proof() -> FreshnessProof {
    FreshnessProof {
        taken_at: at(1_000),
        watermark: 7,
    }
}

#[test]
fn exposes_its_bounds() {
    assert_eq!(rule().hard_bound(), HARD);
    assert_eq!(rule().ready_bound(), READY);
}

#[test]
fn a_pod_without_a_proof_is_stale() {
    assert_eq!(
        rule().judge(at(1_000), None, Duration::ZERO),
        Freshness::Stale(StaleCause::NoProof)
    );
}

#[test]
fn allows_up_to_the_hard_bound_and_not_a_millisecond_longer() {
    let at_bound = rule().judge(at(16_000), Some(&proof()), Duration::ZERO);
    let past_bound = rule().judge(at(16_001), Some(&proof()), Duration::ZERO);

    assert_eq!(at_bound, Freshness::Fresh(HARD));
    assert_eq!(
        past_bound,
        Freshness::Stale(StaleCause::Aged(Duration::from_millis(15_001)))
    );
    assert!(at_bound.is_fresh());
    assert!(!past_bound.is_fresh());
}

#[test]
fn a_gap_above_the_ready_bound_makes_the_proof_stale() {
    let gap = Duration::from_millis(2_001);

    assert_eq!(
        rule().judge(at(2_000), Some(&proof()), gap),
        Freshness::Stale(StaleCause::Gap(gap))
    );
}

#[test]
fn a_gap_equal_to_the_ready_bound_is_tolerated() {
    assert!(rule().judge(at(2_000), Some(&proof()), READY).is_fresh());
}

#[test]
fn the_gap_rule_compares_with_the_ready_bound() {
    assert!(rule().gap_breaks_proof(Duration::from_millis(2_001)));
    assert!(!rule().gap_breaks_proof(READY));
}

#[test]
fn a_fresh_pod_counts_as_current_up_to_the_ready_bound_only() {
    let rule = rule();

    assert!(rule.is_current(true, Some(READY)));
    assert!(!rule.is_current(true, Some(Duration::from_millis(2_001))));
    assert!(!rule.is_current(true, None));
    assert!(!rule.is_current(false, Some(Duration::ZERO)));
}

#[test]
fn the_rule_hands_the_readiness_verdict_to_the_peer_comparison() {
    use crate::freshness::peer_report::{PeerObservation, PeerReport};
    use crate::freshness::readiness::ReadinessVerdict;

    let observation = PeerObservation {
        version: None,
        fresh: true,
        proof_age: Some(Duration::from_millis(100)),
    };
    let peers = [PeerReport::judged(None, observation, &rule())];

    assert!(peers.iter().all(|peer| peer.current));
    assert_eq!(
        FreshnessRule::readiness_verdict(false, None, &peers),
        ReadinessVerdict::Local
    );
}
