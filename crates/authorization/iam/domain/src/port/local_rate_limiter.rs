//! Port of the in-process rate limiter (FR-63, FR-65).

use crate::rate_limit::decision::RateDecision;
use crate::rate_limit::key::RateKey;
use crate::rate_limit::rule::RateDecisionRule;
use crate::value_object::identifier::RatePolicyId;

/// Decides requests from the memory of one gateway pod: the per-IP flood guard that runs before
/// anything else, and the fallback buckets that stand in for the shared counter.
///
/// Neither check fails: the limiter answers admit or reject and never changes who is authorized.
pub trait LocalRateLimiter: std::fmt::Debug + Send + Sync {
    /// Decides one request of the `ip` key against the flood guard.
    fn check_guard(&self, key: &RateKey) -> RateDecision;

    /// Decides one request of `key` against the fallback bucket of `policy_id`, with the
    /// conservative `rule` the caller computed.
    fn check_fallback(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> RateDecision;
}
