//! The composition of the data plane (`service gateway`): its adapters, its task set and its three
//! routers (ADR 0015).
//!
//! The gateway never opens a PostgreSQL pool: [`GatewayAdapters`] holds only the ports the data
//! plane needs, none of which touches a database.

use std::sync::Arc;

use iam_domain::Rng;
use iam_infrastructure::{JwtKeyFileError, JwtKeySet, SeededRng};
use shared_domain::Clock;
use shared_infrastructure::clock::SystemClock;
use tokio::sync::watch;

use super::{TaskMode, TaskSupervisor};
use crate::config::GatewayConfig;

pub mod internal;
pub mod listener;
pub mod probe;

/// Every driven port of the gateway.
pub struct GatewayAdapters {
    /// Source of every random draw of the data plane.
    pub rng: Arc<dyn Rng>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
    /// The public keys that verify access tokens, parsed at start.
    pub keys: JwtKeySet,
}

impl GatewayAdapters {
    /// Wires the production adapters: the random source is seeded from the operating system and
    /// the key file is parsed now, so that a gateway that cannot verify a token does not start.
    ///
    /// # Errors
    ///
    /// Returns the error of reading or parsing `JWT_PUBLIC_KEYS_FILE`.
    pub fn from_config(config: &GatewayConfig) -> Result<Self, JwtKeyFileError> {
        Ok(Self {
            rng: Arc::new(SeededRng::from_os()),
            clock: Arc::new(SystemClock),
            keys: JwtKeySet::load(&config.tokens.public_keys_file)?,
        })
    }
}

impl std::fmt::Debug for GatewayAdapters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayAdapters")
            .field("rng", &self.rng)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

/// The per-replica tasks of the gateway. No story has registered one yet: Story 9.3 adds the
/// first, so the set is empty and the supervisor only waits for what the composition root adds.
///
/// `shutdown` is the stop flag of the service: tasks end when it is set.
#[must_use]
pub fn start_tasks(_adapters: &GatewayAdapters, shutdown: watch::Receiver<bool>) -> TaskSupervisor {
    TaskSupervisor::new(TaskMode::Serve, shutdown)
}

#[cfg(test)]
mod tests;
