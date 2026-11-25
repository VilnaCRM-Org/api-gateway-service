//! What the forwarder remembers between requests (Story 10.5).
//!
//! It holds the requests in flight and the retry budget of each upstream, and the recent answers
//! of each endpoint.
//!
//! The rules are those of the domain (`RetryBudget`, `OutlierRule`, `EndpointHealth`); this type
//! owns the counters and the clock they are read against. The clock is the one of `tokio`, which
//! tests pause.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use iam_domain::{EndpointHealth, ForwardError, OutlierRule, RetryBudget, UpstreamTarget};
use tokio::time::Instant;

/// The counters of one upstream.
#[derive(Debug)]
struct UpstreamState {
    in_flight: u32,
    budget: RetryBudget,
}

/// The upstreams and endpoints that the forwarder has served.
#[derive(Debug)]
pub(super) struct Registry {
    origin: Instant,
    upstreams: Mutex<HashMap<String, UpstreamState>>,
    health: Mutex<HashMap<String, EndpointHealth>>,
}

/// One request that the concurrency limit of its upstream admitted, counted until the permit
/// drops.
#[derive(Debug)]
pub(super) struct Permit {
    registry: Arc<Registry>,
    upstream: String,
}

impl Registry {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            upstreams: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
        })
    }

    /// The milliseconds since the registry was made.
    pub(super) fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Admits one more request to the upstream of `target`, or fails at once with
    /// [`ForwardError::Overloaded`] when its `concurrencyLimit` is reached.
    pub(super) fn admit(self: &Arc<Self>, target: &UpstreamTarget) -> Result<Permit, ForwardError> {
        let admitted = self.with_state(target, |state| {
            let free = state.in_flight < target.concurrency_limit();
            if free {
                state.in_flight = state.in_flight.saturating_add(1);
            }
            free
        });
        if admitted {
            Ok(Permit {
                registry: Arc::clone(self),
                upstream: target.upstream().as_str().to_owned(),
            })
        } else {
            Err(ForwardError::Overloaded)
        }
    }

    /// Counts a request that is sent to the upstream of `target`, a retry included.
    pub(super) fn count_request(&self, target: &UpstreamTarget) {
        self.with_state(target, |state| state.budget.record_request());
    }

    /// Spends one retry of the budget of the upstream of `target`; `false` when it is spent.
    pub(super) fn try_retry(&self, target: &UpstreamTarget) -> bool {
        self.with_state(target, |state| state.budget.try_retry())
    }

    /// The requests in flight to the upstream named `name`.
    #[cfg(test)]
    pub(super) fn in_flight(&self, name: &str) -> u32 {
        lock(&self.upstreams)
            .get(name)
            .map_or(0, |state| state.in_flight)
    }

    /// Whether the endpoint `key` is ejected at `now_ms`.
    pub(super) fn is_ejected(&self, key: &str, now_ms: u64) -> bool {
        lock(&self.health)
            .get(key)
            .is_some_and(|health| health.is_ejected(now_ms))
    }

    /// Counts a good answer of the endpoint `key`.
    pub(super) fn record_success(&self, key: &str) {
        let now_ms = self.now_ms();
        let mut health = lock(&self.health);
        if health
            .get(key)
            .is_some_and(|recorded| !recorded.is_ejected(now_ms))
        {
            health.remove(key);
        }
    }

    /// Counts a failure of the endpoint `key`, which is one of the `offered` endpoints of its
    /// upstream, and ejects it when `rule` says so and fewer than the allowed share is ejected.
    /// Returns whether this call ejected it.
    pub(super) fn record_error(&self, key: &str, rule: &OutlierRule, offered: &[String]) -> bool {
        let now_ms = self.now_ms();
        let mut health = lock(&self.health);
        let ejected = offered
            .iter()
            .filter(|other| {
                health
                    .get(other.as_str())
                    .is_some_and(|recorded| recorded.is_ejected(now_ms))
            })
            .count();
        let allowed = rule.may_eject(ejected, offered.len());
        health
            .entry(key.to_owned())
            .or_default()
            .record_error(rule, now_ms, allowed)
    }

    fn with_state<R, F>(&self, target: &UpstreamTarget, change: F) -> R
    where
        F: FnOnce(&mut UpstreamState) -> R,
    {
        let mut upstreams = lock(&self.upstreams);
        let state = upstreams
            .entry(target.upstream().as_str().to_owned())
            .or_insert_with(|| UpstreamState {
                in_flight: 0,
                budget: RetryBudget::new(target.retry_budget_percent()),
            });
        state.budget = state.budget.with_percent(target.retry_budget_percent());
        let outcome = change(state);
        drop(upstreams);
        outcome
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        lock(&self.registry.upstreams)
            .entry(self.upstream.clone())
            .and_modify(|state| state.in_flight = state.in_flight.saturating_sub(1));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
