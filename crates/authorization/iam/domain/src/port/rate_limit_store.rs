//! Port of the shared rate counters (FR-65).

use shared_domain::BoxError;

use crate::rate_limit::decision::RateDecision;
use crate::rate_limit::key::RateKey;
use crate::rate_limit::rule::RateDecisionRule;
use crate::value_object::identifier::RatePolicyId;

/// The shared counter could not be asked.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitStoreError {
    /// The store cannot be reached, timed out or answered with a failure.
    #[error("the rate limit store is unavailable")]
    Unavailable(#[source] BoxError),
}

/// Decides requests against the counters that every gateway pod shares, so a quota holds across
/// the whole fleet.
///
/// The caller bounds every call with `RATE_LIMIT_STORE_TIMEOUT`; a failure makes it fall back to
/// the [`LocalRateLimiter`](crate::LocalRateLimiter).
#[async_trait::async_trait]
pub trait RateLimitStore: std::fmt::Debug + Send + Sync {
    /// Decides one request of `key` under `policy_id` with `rule` and records an admitted request
    /// in the counter of the key.
    ///
    /// # Errors
    ///
    /// [`RateLimitStoreError::Unavailable`] when the store cannot decide; the counter is then
    /// unchanged as far as the caller knows.
    async fn check(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError>;
}

#[cfg(test)]
mod tests;
