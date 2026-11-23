use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    LocalRateLimiter as _, RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateKeyParts,
    RatePolicyId,
};
use test_support::boot_clock::FakeBootClock;
use test_support::request_digester::FakeRequestDigester;

use super::BucketLocalRateLimiter;

fn ip_key(ip: &str) -> RateKey {
    let parts = RateKeyParts {
        ip: Some(ip),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Ip, &parts, &FakeRequestDigester).unwrap()
}

fn route_key(route: &str) -> RateKey {
    let parts = RateKeyParts {
        route: Some(route),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Route, &parts, &FakeRequestDigester).unwrap()
}

fn policy(number: u32) -> RatePolicyId {
    RatePolicyId::parse(&format!("00000000-0000-7000-8000-{number:012}")).unwrap()
}

/// 10 requests per second with a burst of 5: six requests at one instant pass.
fn guard_rule() -> RateDecisionRule {
    RateDecisionRule::new(10, Duration::from_secs(1), 5)
}

fn limiter(
    capacity: usize,
    rule: RateDecisionRule,
) -> (Arc<FakeBootClock>, BucketLocalRateLimiter) {
    let clock = Arc::new(FakeBootClock::new());
    (
        Arc::clone(&clock),
        BucketLocalRateLimiter::new(clock, rule, capacity),
    )
}

#[test]
fn the_guard_rejects_a_flood_from_one_ip_and_leaves_other_ips_alone() {
    let (_clock, limiter) = limiter(100, guard_rule());
    let flooder = ip_key("203.0.113.1");

    let decisions: Vec<RateDecision> = (0..8).map(|_| limiter.check_guard(&flooder)).collect();

    assert!(decisions[..6].iter().all(|decision| decision.is_admitted()));
    assert_eq!(
        decisions[6],
        RateDecision::Reject {
            retry_after: Duration::from_millis(100)
        }
    );
    assert!(!decisions[7].is_admitted());
    assert!(limiter.check_guard(&ip_key("203.0.113.2")).is_admitted());
}

#[test]
fn the_guard_admits_again_when_the_clock_passes_the_wait() {
    let (clock, limiter) = limiter(100, guard_rule());
    let flooder = ip_key("203.0.113.1");
    for _ in 0..6 {
        assert!(limiter.check_guard(&flooder).is_admitted());
    }
    assert!(!limiter.check_guard(&flooder).is_admitted());

    clock.advance(Duration::from_millis(99));
    assert!(!limiter.check_guard(&flooder).is_admitted());
    clock.advance(Duration::from_millis(1));
    assert!(limiter.check_guard(&flooder).is_admitted());
}

#[test]
fn the_fallback_buckets_are_kept_per_policy_and_per_key() {
    let (_clock, limiter) = limiter(100, guard_rule());
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let key = route_key("login");

    assert!(
        limiter
            .check_fallback(&policy(1), &key, &rule)
            .is_admitted()
    );
    assert!(
        !limiter
            .check_fallback(&policy(1), &key, &rule)
            .is_admitted()
    );
    assert!(
        limiter
            .check_fallback(&policy(2), &key, &rule)
            .is_admitted()
    );
    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("signup"), &rule)
            .is_admitted()
    );
}

#[test]
fn the_guard_and_a_policy_do_not_share_a_bucket_for_the_same_key_hash() {
    let (_clock, limiter) = limiter(100, RateDecisionRule::new(1, Duration::from_secs(60), 0));
    let key = ip_key("203.0.113.1");
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);

    assert!(limiter.check_guard(&key).is_admitted());
    assert!(
        limiter
            .check_fallback(&policy(1), &key, &rule)
            .is_admitted()
    );
}

#[test]
fn a_rejection_does_not_push_the_bucket_further_away() {
    let (clock, limiter) = limiter(100, RateDecisionRule::new(1, Duration::from_secs(10), 0));
    let key = ip_key("203.0.113.1");
    assert!(limiter.check_guard(&key).is_admitted());
    for _ in 0..5 {
        assert!(!limiter.check_guard(&key).is_admitted());
    }

    clock.advance(Duration::from_secs(10));

    assert!(limiter.check_guard(&key).is_admitted());
}

#[test]
fn a_full_map_admits_new_keys_without_a_bucket_until_a_sweep_frees_room() {
    let rule = RateDecisionRule::new(1, Duration::from_millis(500), 0);
    let (clock, limiter) = limiter(1, rule);
    let first = ip_key("203.0.113.1");
    let second = ip_key("203.0.113.2");
    assert!(limiter.check_guard(&first).is_admitted());

    clock.advance(Duration::from_millis(600));
    assert!(limiter.check_guard(&second).is_admitted());
    assert!(limiter.check_guard(&second).is_admitted());

    clock.advance(Duration::from_millis(500));
    assert!(limiter.check_guard(&second).is_admitted());
    assert!(!limiter.check_guard(&second).is_admitted());
    assert!(limiter.check_guard(&first).is_admitted());
}

#[test]
fn a_known_key_keeps_its_bucket_in_a_full_map() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, rule);
    let key = ip_key("203.0.113.1");

    assert!(limiter.check_guard(&key).is_admitted());
    assert!(!limiter.check_guard(&key).is_admitted());
}
