use std::time::Duration;

use iam_domain::{
    LocalRateLimiter as _, RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateKeyParts,
    RatePolicyId,
};

use super::{FakeLocalRateLimiter, FallbackCall};
use crate::request_digester::FakeRequestDigester;

fn key() -> RateKey {
    let parts = RateKeyParts {
        ip: Some("203.0.113.1"),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Ip, &parts, &FakeRequestDigester).unwrap()
}

fn policy() -> RatePolicyId {
    RatePolicyId::parse("00000000-0000-7000-8000-000000000001").unwrap()
}

fn rule() -> RateDecisionRule {
    RateDecisionRule::new(10, Duration::from_secs(1), 0)
}

#[test]
fn admits_and_records_both_kinds_of_check_by_default() {
    let limiter = FakeLocalRateLimiter::new();

    assert_eq!(limiter.check_guard(&key()), RateDecision::Admit);
    assert_eq!(
        limiter.check_fallback(&policy(), &key(), &rule()),
        RateDecision::Admit
    );
    assert_eq!(limiter.guard_calls(), [key()]);
    assert_eq!(
        limiter.fallback_calls(),
        [FallbackCall {
            policy_id: policy(),
            key: key(),
            rule: rule()
        }]
    );
}

#[test]
fn a_failing_limiter_rejects_every_check() {
    let limiter = FakeLocalRateLimiter::failing();
    let rejected = RateDecision::Reject {
        retry_after: Duration::from_secs(1),
    };

    assert_eq!(limiter.check_guard(&key()), rejected);
    assert_eq!(limiter.check_fallback(&policy(), &key(), &rule()), rejected);
}

#[test]
fn answers_the_decision_it_was_given_and_keeps_the_calls_already_recorded() {
    let limiter = FakeLocalRateLimiter::default();
    limiter.check_guard(&key());
    let reject = RateDecision::Reject {
        retry_after: Duration::from_secs(5),
    };

    let limiter = limiter.with_decision(reject);

    assert_eq!(limiter.check_guard(&key()), reject);
    assert_eq!(limiter.guard_calls().len(), 2);
}
