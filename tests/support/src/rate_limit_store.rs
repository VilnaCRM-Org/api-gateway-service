//! Shared rate counter double.

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    RateDecision, RateDecisionRule, RateKey, RateLimitStore, RateLimitStoreError, RatePolicyId,
};

/// One call the double received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCall {
    /// The policy that was checked.
    pub policy_id: RatePolicyId,
    /// The key that was checked.
    pub key: RateKey,
    /// The rule that was applied.
    pub rule: RateDecisionRule,
}

/// A rate limit store that answers one decision for every request, or fails, and records its
/// calls.
#[derive(Debug)]
pub struct FakeRateLimitStore {
    decision: RateDecision,
    failing: bool,
    calls: Mutex<Vec<StoreCall>>,
}

impl FakeRateLimitStore {
    /// A store that admits every request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            decision: RateDecision::Admit,
            failing: false,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A store that is unavailable for every call.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            decision: RateDecision::Admit,
            failing: true,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The same store answering `decision` to every request.
    #[must_use]
    pub const fn with_decision(mut self, decision: RateDecision) -> Self {
        self.decision = decision;
        self
    }

    /// The calls received so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<StoreCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Default for FakeRateLimitStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RateLimitStore for FakeRateLimitStore {
    async fn check(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(StoreCall {
                policy_id: *policy_id,
                key: key.clone(),
                rule: *rule,
            });
        if self.failing {
            return Err(RateLimitStoreError::Unavailable("store is down".into()));
        }
        Ok(self.decision)
    }
}

#[cfg(test)]
mod tests;
