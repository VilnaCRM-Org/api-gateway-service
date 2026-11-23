use std::time::Duration;

use iam_domain::{
    RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateKeyParts, RateLimitStore as _,
    RateLimitStoreError, RatePolicyId,
};

use super::{FakeRateLimitStore, StoreCall};
use crate::block_on;
use crate::request_digester::FakeRequestDigester;

fn key() -> RateKey {
    let parts = RateKeyParts {
        route: Some("login"),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Route, &parts, &FakeRequestDigester).unwrap()
}

fn policy() -> RatePolicyId {
    RatePolicyId::parse("00000000-0000-7000-8000-000000000001").unwrap()
}

fn rule() -> RateDecisionRule {
    RateDecisionRule::new(10, Duration::from_secs(1), 0)
}

#[test]
fn admits_and_records_the_call_by_default() {
    let store = FakeRateLimitStore::new();

    let decision = block_on(store.check(&policy(), &key(), &rule())).unwrap();

    assert_eq!(decision, RateDecision::Admit);
    assert_eq!(
        store.calls(),
        [StoreCall {
            policy_id: policy(),
            key: key(),
            rule: rule()
        }]
    );
}

#[test]
fn answers_the_decision_it_was_given() {
    let reject = RateDecision::Reject {
        retry_after: Duration::from_secs(2),
    };
    let store = FakeRateLimitStore::default().with_decision(reject);

    assert_eq!(
        block_on(store.check(&policy(), &key(), &rule())).unwrap(),
        reject
    );
}

#[test]
fn a_failing_store_is_unavailable_and_still_records_the_call() {
    let store = FakeRateLimitStore::failing();

    let result = block_on(store.check(&policy(), &key(), &rule()));

    assert!(matches!(result, Err(RateLimitStoreError::Unavailable(_))));
    assert_eq!(store.calls().len(), 1);
}
