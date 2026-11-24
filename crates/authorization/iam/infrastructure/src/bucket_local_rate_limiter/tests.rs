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
fn a_full_pool_decides_new_keys_against_one_shared_overflow_bucket() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, rule);
    let first = ip_key("203.0.113.1");
    assert!(limiter.check_guard(&first).is_admitted());

    // The pool is full: the second key is not skipped but limited by the overflow bucket.
    assert!(limiter.check_guard(&ip_key("203.0.113.2")).is_admitted());
    assert!(!limiter.check_guard(&ip_key("203.0.113.3")).is_admitted());
    assert!(!limiter.check_guard(&ip_key("203.0.113.2")).is_admitted());
    // The key that owns a bucket is still decided by its own bucket.
    assert!(!limiter.check_guard(&first).is_admitted());
}

#[test]
fn the_overflow_bucket_admits_again_when_the_clock_passes_the_wait() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(10), 0);
    let (clock, limiter) = limiter(1, rule);
    assert!(limiter.check_guard(&ip_key("203.0.113.1")).is_admitted());
    assert!(limiter.check_guard(&ip_key("203.0.113.2")).is_admitted());
    assert!(!limiter.check_guard(&ip_key("203.0.113.3")).is_admitted());

    clock.advance(Duration::from_secs(10));

    assert!(limiter.check_guard(&ip_key("203.0.113.3")).is_admitted());
}

#[test]
fn a_sweep_frees_room_in_a_full_pool_for_a_new_key() {
    let rule = RateDecisionRule::new(1, Duration::from_millis(500), 0);
    let (clock, limiter) = limiter(1, rule);
    let first = ip_key("203.0.113.1");
    let second = ip_key("203.0.113.2");
    assert!(limiter.check_guard(&first).is_admitted());

    clock.advance(Duration::from_millis(600));
    assert!(limiter.check_guard(&second).is_admitted());
    // The sweep dropped the idle bucket of the first key, so the second key owns a bucket now.
    assert!(!limiter.check_guard(&second).is_admitted());
}

#[test]
fn the_policy_pool_is_full_independently_of_the_guard_pool() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, rule);
    for number in 0..4 {
        assert!(
            limiter
                .check_guard(&ip_key(&format!("203.0.113.{number}")))
                .is_admitted()
                || number > 0
        );
    }

    // The flooded guard pool leaves the policy pool empty: the first policy key owns a bucket.
    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("login"), &rule)
            .is_admitted()
    );
    assert!(
        !limiter
            .check_fallback(&policy(1), &route_key("login"), &rule)
            .is_admitted()
    );
}

#[test]
fn a_full_policy_pool_does_not_limit_the_guard() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, guard_rule());
    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("a"), &rule)
            .is_admitted()
    );
    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("b"), &rule)
            .is_admitted()
    );
    assert!(
        !limiter
            .check_fallback(&policy(1), &route_key("c"), &rule)
            .is_admitted()
    );

    assert!(limiter.check_guard(&ip_key("203.0.113.1")).is_admitted());
    assert!(limiter.check_guard(&ip_key("203.0.113.1")).is_admitted());
}

#[test]
fn every_policy_has_its_own_overflow_bucket() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, guard_rule());
    // Fill the shared policy pool with a key of policy 1.
    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("owner"), &rule)
            .is_admitted()
    );

    assert!(
        limiter
            .check_fallback(&policy(1), &route_key("a"), &rule)
            .is_admitted()
    );
    assert!(
        !limiter
            .check_fallback(&policy(1), &route_key("b"), &rule)
            .is_admitted()
    );
    assert!(
        limiter
            .check_fallback(&policy(2), &route_key("a"), &rule)
            .is_admitted()
    );
}

#[test]
fn a_known_key_keeps_its_bucket_in_a_full_map() {
    let rule = RateDecisionRule::new(1, Duration::from_secs(60), 0);
    let (_clock, limiter) = limiter(1, rule);
    let key = ip_key("203.0.113.1");

    assert!(limiter.check_guard(&key).is_admitted());
    assert!(!limiter.check_guard(&key).is_admitted());
}
