//! Local rate limiter double.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{LocalRateLimiter, RateDecision, RateDecisionRule, RateKey, RatePolicyId};

/// A fallback check the double received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackCall {
    /// The policy that was checked.
    pub policy_id: RatePolicyId,
    /// The key that was checked.
    pub key: RateKey,
    /// The conservative rule that was applied.
    pub rule: RateDecisionRule,
}

#[derive(Debug, Default)]
struct Book {
    guards: Vec<RateKey>,
    fallbacks: Vec<FallbackCall>,
}

/// A local limiter that answers one decision for every check and records its calls.
///
/// [`Self::new`] admits everything; [`Self::failing`] is the limiter in its failure mode, which
/// rejects everything.
#[derive(Debug)]
pub struct FakeLocalRateLimiter {
    decision: RateDecision,
    book: Mutex<Book>,
}

impl FakeLocalRateLimiter {
    /// A limiter that admits every request.
    #[must_use]
    pub const fn new() -> Self {
        Self::answering(RateDecision::Admit)
    }

    /// A limiter that rejects every request, asking the caller to retry in one second.
    #[must_use]
    pub const fn failing() -> Self {
        Self::answering(RateDecision::Reject {
            retry_after: Duration::from_secs(1),
        })
    }

    /// The same limiter answering `decision` to every check.
    #[must_use]
    pub const fn with_decision(mut self, decision: RateDecision) -> Self {
        self.decision = decision;
        self
    }

    const fn answering(decision: RateDecision) -> Self {
        Self {
            decision,
            book: Mutex::new(Book {
                guards: Vec::new(),
                fallbacks: Vec::new(),
            }),
        }
    }

    /// The keys checked against the flood guard, in order.
    #[must_use]
    pub fn guard_calls(&self) -> Vec<RateKey> {
        self.book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .guards
            .clone()
    }

    /// The fallback checks received, in order.
    #[must_use]
    pub fn fallback_calls(&self) -> Vec<FallbackCall> {
        self.book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fallbacks
            .clone()
    }
}

impl Default for FakeLocalRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalRateLimiter for FakeLocalRateLimiter {
    fn check_guard(&self, key: &RateKey) -> RateDecision {
        self.book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .guards
            .push(key.clone());
        self.decision
    }

    fn check_fallback(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> RateDecision {
        self.book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fallbacks
            .push(FallbackCall {
                policy_id: *policy_id,
                key: key.clone(),
                rule: *rule,
            });
        self.decision
    }
}

#[cfg(test)]
mod tests;
