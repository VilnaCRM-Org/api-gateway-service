use std::time::Duration;

use proptest::prelude::{Strategy, any};
use rstest::rstest;

use super::{RateDecisionRule, RateOutcome};
use crate::rate_limit::decision::RateDecision;
use crate::rate_policy::fields::{RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields};
use crate::value_object::boot_instant::BootInstant;

fn at(millis: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_millis(millis))
}

fn fields(limit: i64, burst: i64, fallback: RateFallback) -> RatePolicyFields {
    RatePolicyFields::new(RatePolicyDraft {
        name: "policy".to_owned(),
        key_kind: RateKeyKind::Ip,
        limit,
        period_seconds: 60,
        burst,
        fallback,
    })
    .unwrap()
}

/// Feeds the arrivals to the rule, as one key, and returns what it decided.
fn run(rule: &RateDecisionRule, arrivals: &[u64]) -> Vec<RateDecision> {
    let mut arrival = RateDecisionRule::UNSEEN;
    arrivals
        .iter()
        .map(|millis| {
            let RateOutcome {
                decision,
                theoretical_arrival,
            } = rule.decide(arrival, at(*millis));
            arrival = theoretical_arrival;
            decision
        })
        .collect()
}

fn reject(millis: u64) -> RateDecision {
    RateDecision::Reject {
        retry_after: Duration::from_millis(millis),
    }
}

#[test]
fn derives_the_emission_interval_and_the_tolerance_from_limit_period_and_burst() {
    let rule = RateDecisionRule::new(100, Duration::from_millis(60_000), 20);

    assert_eq!(rule.emission_interval(), Duration::from_millis(600));
    assert_eq!(rule.tolerance(), Duration::from_secs(12));
}

#[test]
fn rounds_the_emission_interval_up_to_a_nanosecond() {
    let rule = RateDecisionRule::new(3, Duration::from_nanos(10), 0);

    assert_eq!(rule.emission_interval(), Duration::from_nanos(4));
    assert_eq!(
        RateDecisionRule::new(u32::MAX, Duration::from_nanos(1), 0).emission_interval(),
        Duration::from_nanos(1)
    );
}

#[test]
fn reads_a_limit_of_zero_as_one() {
    assert_eq!(
        RateDecisionRule::new(0, Duration::from_secs(1), 0),
        RateDecisionRule::new(1, Duration::from_secs(1), 0)
    );
}

#[test]
fn saturates_an_interval_that_does_not_fit() {
    let rule = RateDecisionRule::new(1, Duration::MAX, 2);

    assert_eq!(rule.emission_interval(), Duration::MAX);
    assert_eq!(rule.tolerance(), Duration::MAX);
}

#[test]
fn admits_exactly_what_gcra_admits_for_a_limit_of_two_with_a_burst_of_one() {
    let rule = RateDecisionRule::new(2, Duration::from_millis(1_000), 1);

    let decisions = run(&rule, &[0, 0, 0, 500, 500, 1_000]);

    assert_eq!(
        decisions,
        [
            RateDecision::Admit,
            RateDecision::Admit,
            reject(500),
            RateDecision::Admit,
            reject(500),
            RateDecision::Admit,
        ]
    );
}

#[test]
fn a_rejection_leaves_the_theoretical_arrival_time_unchanged() {
    let rule = RateDecisionRule::new(1, Duration::from_millis(1_000), 0);
    let first = rule.decide(RateDecisionRule::UNSEEN, at(0));
    let rejected = rule.decide(first.theoretical_arrival, at(0));

    assert_eq!(rejected.decision, reject(1_000));
    assert_eq!(rejected.theoretical_arrival, first.theoretical_arrival);
    assert_eq!(first.theoretical_arrival, at(1_000));
}

#[rstest]
#[case::at_the_same_instant(0, reject(1_000))]
#[case::just_before_the_interval_ends(999, reject(1))]
#[case::when_the_interval_ends(1_000, RateDecision::Admit)]
fn a_burst_of_zero_admits_one_request_per_interval(
    #[case] second_arrival: u64,
    #[case] expected: RateDecision,
) {
    let rule = RateDecisionRule::new(1, Duration::from_millis(1_000), 0);

    assert_eq!(
        run(&rule, &[0, second_arrival]),
        [RateDecision::Admit, expected]
    );
}

#[test]
fn admits_a_burst_above_the_steady_rate_and_then_rejects_with_the_computed_wait() {
    let rule = RateDecisionRule::new(100, Duration::from_millis(60_000), 20);
    let arrivals = [1_000_000; 23];

    let decisions = run(&rule, &arrivals);

    assert!(
        decisions[..21]
            .iter()
            .all(|decision| decision.is_admitted())
    );
    assert_eq!(decisions[21], reject(600));
    assert_eq!(decisions[22], reject(600));
}

#[test]
fn an_idle_key_starts_from_a_full_burst() {
    let rule = RateDecisionRule::new(1, Duration::from_millis(1_000), 1);

    let decisions = run(&rule, &[0, 0, 0, 100_000, 100_000, 100_000]);

    assert_eq!(
        decisions,
        [
            RateDecision::Admit,
            RateDecision::Admit,
            reject(1_000),
            RateDecision::Admit,
            RateDecision::Admit,
            reject(1_000),
        ]
    );
}

#[test]
fn a_theoretical_arrival_that_cannot_be_represented_saturates() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(1), 0);
    let end = BootInstant::from_elapsed(Duration::MAX);

    let outcome = rule.decide(RateDecisionRule::UNSEEN, end);

    assert_eq!(outcome.decision, RateDecision::Admit);
    assert_eq!(outcome.theoretical_arrival, end);
}

#[test]
fn builds_the_rule_of_a_policy_from_its_fields() {
    assert_eq!(
        RateDecisionRule::for_policy(&fields(100, 20, RateFallback::Divided)),
        RateDecisionRule::new(100, Duration::from_secs(60), 20)
    );
}

#[rstest]
#[case::six_pods_divided(RateFallback::Divided, 6, 16)]
#[case::one_pod_divided(RateFallback::Divided, 1, 100)]
#[case::no_ready_pod_is_read_as_one(RateFallback::Divided, 0, 100)]
#[case::full_ignores_the_pods(RateFallback::Full, 6, 100)]
#[case::full_without_pods(RateFallback::Full, 0, 100)]
#[case::never_below_one(RateFallback::Divided, 1_000, 1)]
fn computes_the_conservative_limit(
    #[case] fallback: RateFallback,
    #[case] ready: u32,
    #[case] expected: u32,
) {
    assert_eq!(
        RateDecisionRule::conservative_limit(100, fallback, ready),
        expected
    );
}

#[test]
fn builds_the_conservative_rule_with_the_period_and_the_burst_of_the_policy() {
    let policy = fields(100, 20, RateFallback::Divided);

    assert_eq!(
        RateDecisionRule::conservative(&policy, 6),
        RateDecisionRule::new(16, Duration::from_secs(60), 20)
    );
    assert_eq!(
        RateDecisionRule::conservative(&fields(100, 20, RateFallback::Full), 6),
        RateDecisionRule::new(100, Duration::from_secs(60), 20)
    );
}

fn arrivals() -> impl Strategy<Value = Vec<u64>> {
    proptest::collection::vec(0_u64..2_000, 1..200).prop_map(|gaps| {
        gaps.into_iter()
            .scan(0_u64, |now, gap| {
                *now = now.saturating_add(gap);
                Some(*now)
            })
            .collect()
    })
}

proptest::proptest! {
    #[test]
    fn never_admits_more_than_limit_plus_burst_in_a_window_of_one_period(
        limit in 1_u32..=20,
        period_millis in 100_u64..=5_000,
        burst in 0_u32..=10,
        arrivals in arrivals(),
        base in any::<u16>(),
    ) {
        let period = Duration::from_millis(period_millis);
        let rule = RateDecisionRule::new(limit, period, burst);
        let shifted: Vec<u64> = arrivals.iter().map(|at| at.saturating_add(u64::from(base))).collect();
        let admitted: Vec<u64> = run(&rule, &shifted)
            .into_iter()
            .zip(&shifted)
            .filter(|(decision, _)| decision.is_admitted())
            .map(|(_, at)| *at)
            .collect();

        for start in &admitted {
            let in_window = admitted
                .iter()
                .filter(|at| *at >= start && at.saturating_sub(*start) < period_millis)
                .count();
            proptest::prop_assert!(in_window <= usize::try_from(limit.saturating_add(burst)).unwrap());
        }
    }
}
