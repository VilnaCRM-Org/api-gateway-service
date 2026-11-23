//! The in-process rate limiter: the per-IP flood guard and the fallback buckets of the rate
//! policies (FR-63, FR-65).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use iam_domain::{
    BootClock, BootInstant, LocalRateLimiter, RateDecision, RateDecisionRule, RateKey, RatePolicyId,
};

/// The time between two sweeps of the buckets that are idle again.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// What a bucket belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Scope {
    /// The flood guard.
    Guard,
    /// The fallback of one rate policy.
    Policy(RatePolicyId),
}

/// A bucket: its scope and the hash of the key it counts.
type BucketId = (Scope, String);

#[derive(Debug)]
struct Buckets {
    /// The theoretical arrival time of every bucket that is not idle.
    arrivals: HashMap<BucketId, BootInstant>,
    swept_at: BootInstant,
}

/// Applies the [`RateDecisionRule`] over [`BootClock`] instants to buckets kept in a standard
/// map.
///
/// The guard rule is sized well above any policy (configuration), so only a flood from one address
/// reaches it. The map holds at most `capacity` buckets: a bucket that is idle again is the same as
/// no bucket, and a sweep, at most once per second, drops those when the map is full. A request
/// whose key finds the map full of busy buckets is admitted without a bucket of its own, so a flood
/// of distinct keys can neither grow the memory nor lock the other keys out.
#[derive(Debug)]
pub struct BucketLocalRateLimiter {
    clock: Arc<dyn BootClock>,
    guard_rule: RateDecisionRule,
    capacity: usize,
    buckets: Mutex<Buckets>,
}

impl BucketLocalRateLimiter {
    /// A limiter whose flood guard applies `guard_rule` and that keeps at most `capacity` buckets.
    #[must_use]
    pub fn new(clock: Arc<dyn BootClock>, guard_rule: RateDecisionRule, capacity: usize) -> Self {
        let swept_at = clock.now();
        Self {
            clock,
            guard_rule,
            capacity,
            buckets: Mutex::new(Buckets {
                arrivals: HashMap::new(),
                swept_at,
            }),
        }
    }

    fn locked(&self) -> MutexGuard<'_, Buckets> {
        self.buckets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Decides one request of the bucket `id` under `rule`.
    fn decide(&self, id: BucketId, rule: &RateDecisionRule) -> RateDecision {
        let now = self.clock.now();
        let mut buckets = self.locked();
        let arrival = buckets
            .arrivals
            .get(&id)
            .copied()
            .unwrap_or(RateDecisionRule::UNSEEN);
        let outcome = rule.decide(arrival, now);
        if outcome.decision.is_admitted() {
            self.keep(&mut buckets, id, outcome.theoretical_arrival, now);
        }
        drop(buckets);
        outcome.decision
    }

    /// Keeps the arrival time of the bucket when the map has room for it.
    fn keep(&self, buckets: &mut Buckets, id: BucketId, arrival: BootInstant, now: BootInstant) {
        let known = buckets.arrivals.contains_key(&id);
        if !known
            && buckets.arrivals.len() >= self.capacity
            && now.saturating_since(buckets.swept_at) >= SWEEP_INTERVAL
        {
            buckets.arrivals.retain(|_, theoretical| *theoretical > now);
            buckets.swept_at = now;
        }
        if known || buckets.arrivals.len() < self.capacity {
            buckets.arrivals.insert(id, arrival);
        }
    }
}

impl LocalRateLimiter for BucketLocalRateLimiter {
    fn check_guard(&self, key: &RateKey) -> RateDecision {
        self.decide((Scope::Guard, key.key_hash().to_owned()), &self.guard_rule)
    }

    fn check_fallback(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> RateDecision {
        self.decide((Scope::Policy(*policy_id), key.key_hash().to_owned()), rule)
    }
}

#[cfg(test)]
mod tests;
