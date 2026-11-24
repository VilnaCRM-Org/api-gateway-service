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

/// The buckets of one capacity pool.
#[derive(Debug)]
struct Pool {
    /// The theoretical arrival time of every bucket that is not idle.
    arrivals: HashMap<BucketId, BootInstant>,
    swept_at: BootInstant,
}

impl Pool {
    fn new(swept_at: BootInstant) -> Self {
        Self {
            arrivals: HashMap::new(),
            swept_at,
        }
    }

    /// Whether a bucket for `id` can be kept: it is known, or the pool has room, possibly after a
    /// sweep of the buckets that are idle again (at most once per [`SWEEP_INTERVAL`]).
    fn has_room_for(&mut self, id: &BucketId, capacity: usize, now: BootInstant) -> bool {
        if self.arrivals.contains_key(id) {
            return true;
        }
        if self.arrivals.len() >= capacity && now.saturating_since(self.swept_at) >= SWEEP_INTERVAL
        {
            self.arrivals.retain(|_, theoretical| *theoretical > now);
            self.swept_at = now;
        }
        self.arrivals.len() < capacity
    }
}

#[derive(Debug)]
struct Buckets {
    /// The pool of the flood guard.
    guard: Pool,
    /// The pool of the fallback buckets of every rate policy.
    policies: Pool,
    /// The one shared bucket per scope that decides the keys a full pool has no room for.
    overflow: HashMap<Scope, BootInstant>,
}

impl Buckets {
    const fn pool_mut(&mut self, scope: &Scope) -> &mut Pool {
        match scope {
            Scope::Guard => &mut self.guard,
            Scope::Policy(_) => &mut self.policies,
        }
    }
}

/// Applies the [`RateDecisionRule`] over [`BootClock`] instants to buckets kept in a standard
/// map.
///
/// The guard rule is sized well above any policy (configuration), so only a flood from one address
/// reaches it. The guard buckets and the policy fallback buckets live in separate pools of at most
/// `capacity` buckets each, so a flood of one kind cannot crowd out the other. A bucket that is
/// idle again is the same as no bucket, and a sweep, at most once per second, drops those when a
/// pool is full. A request whose key finds its pool full of busy buckets is never skipped: it is
/// decided against one shared overflow bucket of its scope (the guard, or the policy) under the
/// same rule, so a flood of distinct keys can neither grow the memory nor pass unlimited.
#[derive(Debug)]
pub struct BucketLocalRateLimiter {
    clock: Arc<dyn BootClock>,
    guard_rule: RateDecisionRule,
    capacity: usize,
    buckets: Mutex<Buckets>,
}

impl BucketLocalRateLimiter {
    /// A limiter whose flood guard applies `guard_rule` and that keeps at most `capacity` buckets
    /// in each of its two pools.
    #[must_use]
    pub fn new(clock: Arc<dyn BootClock>, guard_rule: RateDecisionRule, capacity: usize) -> Self {
        let swept_at = clock.now();
        Self {
            clock,
            guard_rule,
            capacity,
            buckets: Mutex::new(Buckets {
                guard: Pool::new(swept_at),
                policies: Pool::new(swept_at),
                overflow: HashMap::new(),
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
        let scope = id.0.clone();
        let pool = buckets.pool_mut(&scope);
        let decision = if pool.has_room_for(&id, self.capacity, now) {
            let arrival = pool
                .arrivals
                .get(&id)
                .copied()
                .unwrap_or(RateDecisionRule::UNSEEN);
            let outcome = rule.decide(arrival, now);
            if outcome.decision.is_admitted() {
                pool.arrivals.insert(id, outcome.theoretical_arrival);
            }
            outcome.decision
        } else {
            Self::decide_overflow(&mut buckets, scope, rule, now)
        };
        drop(buckets);
        decision
    }

    /// Decides a request whose pool is full against the shared overflow bucket of its scope.
    fn decide_overflow(
        buckets: &mut Buckets,
        scope: Scope,
        rule: &RateDecisionRule,
        now: BootInstant,
    ) -> RateDecision {
        let arrival = buckets
            .overflow
            .get(&scope)
            .copied()
            .unwrap_or(RateDecisionRule::UNSEEN);
        let outcome = rule.decide(arrival, now);
        if outcome.decision.is_admitted() {
            buckets.overflow.insert(scope, outcome.theoretical_arrival);
        }
        outcome.decision
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
