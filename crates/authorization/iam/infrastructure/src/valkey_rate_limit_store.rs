//! The shared rate counters in Valkey (Story 12.2, FR-65).
//!
//! One `EVALSHA` of the GCRA script per policy and request decides the request on the key
//! `rl:<policyId>:<keyHash>`, whose theoretical arrival time lives as long as it lies in the future.
//! The script reads the time of the server, so every pod of the fleet decides on one clock. When
//! the server has lost the script (`SCRIPT FLUSH`, a restart) the first call answers `NOSCRIPT`,
//! the script is loaded again and the same request is decided normally.
//!
//! The adapter keeps one multiplexed connection and drops it after a failure, so the next call
//! connects again (to the new master after a Sentinel failover). The application bounds every call
//! with `RATE_LIMIT_STORE_TIMEOUT` and drops the future of a call that is too slow; a guard of the
//! call then drops the connection as well, because a connection that hangs would otherwise stay
//! cached and fail every later call. The connection also carries a connect timeout and a response
//! timeout of its own.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use iam_domain::{
    RateDecision, RateDecisionRule, RateKey, RateLimitStore, RateLimitStoreError, RatePolicyId,
};
use redis::Script;
use redis::aio::MultiplexedConnection;
use shared_domain::BoxError;

mod endpoint;

pub use endpoint::{InvalidValkeyUrl, ValkeyEndpoint};

/// The GCRA script, loaded by its digest.
const GCRA_SCRIPT: &str = include_str!("valkey_rate_limit_store/script.lua");

/// The shared counter in Valkey.
pub struct ValkeyRateLimitStore {
    endpoint: ValkeyEndpoint,
    script: Script,
    connection: Mutex<Option<MultiplexedConnection>>,
}

impl ValkeyRateLimitStore {
    /// A store over `endpoint`; it connects on its first call.
    #[must_use]
    pub fn new(endpoint: ValkeyEndpoint) -> Self {
        Self {
            endpoint,
            script: Script::new(GCRA_SCRIPT),
            connection: Mutex::new(None),
        }
    }

    /// The key of one counter: the policy and the hash of the key parts, nothing else.
    #[must_use]
    pub fn key_of(policy_id: &RatePolicyId, key: &RateKey) -> String {
        format!("rl:{policy_id}:{}", key.key_hash())
    }

    fn cached(&self) -> Option<MultiplexedConnection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn keep(&self, connection: Option<MultiplexedConnection>) {
        *self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = connection;
    }

    async fn connected(&self) -> redis::RedisResult<MultiplexedConnection> {
        if let Some(connection) = self.cached() {
            return Ok(connection);
        }
        let fresh = self.endpoint.connect().await?;
        self.keep(Some(fresh.clone()));
        Ok(fresh)
    }

    async fn decide(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        let mut connection = self.connected().await.map_err(unavailable)?;
        let mut guard = DropConnection::armed(self);
        let reply: (i64, i64) = self
            .script
            .key(Self::key_of(policy_id, key))
            .arg(micros_up(rule.emission_interval()))
            .arg(micros_up(rule.tolerance()))
            .invoke_async(&mut connection)
            .await
            .map_err(unavailable)?;
        guard.disarm();
        Ok(decision_of(reply))
    }
}

/// Drops the cached connection of the store unless it is disarmed, which a call does only once
/// the server answered: a call that fails, or whose future its caller drops, leaves the guard
/// armed.
struct DropConnection<'store> {
    store: &'store ValkeyRateLimitStore,
    armed: bool,
}

impl<'store> DropConnection<'store> {
    const fn armed(store: &'store ValkeyRateLimitStore) -> Self {
        Self { store, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DropConnection<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.keep(None);
        }
    }
}

impl std::fmt::Debug for ValkeyRateLimitStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValkeyRateLimitStore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RateLimitStore for ValkeyRateLimitStore {
    async fn check(
        &self,
        policy_id: &RatePolicyId,
        key: &RateKey,
        rule: &RateDecisionRule,
    ) -> Result<RateDecision, RateLimitStoreError> {
        self.decide(policy_id, key, rule).await
    }
}

/// The duration in whole microseconds, rounded up and at least 1, the unit of the script.
fn micros_up(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos().div_ceil(1_000))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// What the script answered: `{1, 0}` admits, `{0, retry_after}` rejects.
fn decision_of((admitted, retry_after_micros): (i64, i64)) -> RateDecision {
    if admitted == 1 {
        return RateDecision::Admit;
    }
    RateDecision::Reject {
        retry_after: Duration::from_micros(u64::try_from(retry_after_micros).unwrap_or(0)),
    }
}

fn unavailable(error: redis::RedisError) -> RateLimitStoreError {
    let source: BoxError = Box::new(error);
    RateLimitStoreError::Unavailable(source)
}

#[cfg(test)]
mod tests;
