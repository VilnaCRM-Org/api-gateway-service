use std::time::Duration;

use iam_domain::{
    RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateKeyParts, RateLimitStore as _,
    RateLimitStoreError, RatePolicyId,
};
use test_support::request_digester::FakeRequestDigester;

use super::{GCRA_SCRIPT, ValkeyEndpoint, ValkeyRateLimitStore, decision_of, micros_up};

fn policy() -> RatePolicyId {
    RatePolicyId::parse("0197b6c4-5d4a-7a52-8f0e-2d2f4f1c9a11").unwrap()
}

fn key() -> RateKey {
    let parts = RateKeyParts {
        ip: Some("203.0.113.9"),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Ip, &parts, &FakeRequestDigester).unwrap()
}

#[test]
fn a_key_is_the_policy_and_the_hash_of_the_key_parts() {
    let key = key();

    let text = ValkeyRateLimitStore::key_of(&policy(), &key);

    assert_eq!(
        text,
        format!("rl:0197b6c4-5d4a-7a52-8f0e-2d2f4f1c9a11:{}", key.key_hash())
    );
    assert!(!text.contains("203.0.113.9"));
}

#[test]
fn durations_reach_the_script_in_whole_microseconds_rounded_up() {
    assert_eq!(micros_up(Duration::from_millis(100)), 100_000);
    assert_eq!(micros_up(Duration::from_nanos(1_001)), 2);
    assert_eq!(micros_up(Duration::from_nanos(1)), 1);
    assert_eq!(micros_up(Duration::ZERO), 1);
    assert_eq!(micros_up(Duration::MAX), u64::MAX);
}

#[test]
fn the_reply_of_the_script_is_a_decision() {
    assert_eq!(decision_of((1, 0)), RateDecision::Admit);
    assert_eq!(
        decision_of((0, 250_000)),
        RateDecision::Reject {
            retry_after: Duration::from_millis(250)
        }
    );
    assert_eq!(
        decision_of((0, -1)),
        RateDecision::Reject {
            retry_after: Duration::ZERO
        }
    );
}

#[test]
fn the_script_reads_the_server_clock_and_writes_one_key_with_an_expiry() {
    assert!(GCRA_SCRIPT.contains("redis.call('TIME')"));
    assert_eq!(GCRA_SCRIPT.matches("redis.call('SET'").count(), 1);
    assert!(GCRA_SCRIPT.contains("'PX'"));
}

#[tokio::test]
async fn a_server_that_cannot_be_reached_makes_the_store_unavailable() {
    let store = ValkeyRateLimitStore::new(ValkeyEndpoint::Direct("redis://127.0.0.1:1".to_owned()));
    let rule = RateDecisionRule::new(10, Duration::from_secs(1), 0);

    let outcome = store.check(&policy(), &key(), &rule).await;

    assert!(matches!(outcome, Err(RateLimitStoreError::Unavailable(_))));
    assert_eq!(format!("{store:?}"), "ValkeyRateLimitStore { .. }");
}
