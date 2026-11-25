//! The composition of the data plane (`service gateway`): its adapters, its task set and its three
//! routers (ADR 0015).
//!
//! The gateway never opens a PostgreSQL pool: [`GatewayAdapters`] holds only the ports the data
//! plane needs, none of which touches a database.

use std::sync::Arc;

use iam_application::{EndpointWatcher, WatcherSettings};
use iam_domain::Rng;
use iam_infrastructure::{JwtKeyFileError, JwtKeySet, SeededRng};
use shared_domain::Clock;
use shared_infrastructure::clock::SystemClock;
use tokio::sync::watch;

use self::access_log::AccessLogAdapters;
use self::endpoints::{EndpointAdapters, EndpointSetupError};
use self::policy::PolicyAdapters;
use self::readiness::ReadinessAdapters;
use super::{TaskMode, TaskSupervisor};
use crate::config::GatewayConfig;

pub mod access_log;
pub mod apply_thread;
pub mod decision;
pub mod endpoints;
pub mod freshness;
pub mod internal;
pub mod listener;
pub mod pipeline;
pub mod policy;
pub mod probe;
pub mod readiness;
pub mod shedding;
pub mod upstream;

/// Every driven port of the gateway.
pub struct GatewayAdapters {
    /// Source of every random draw of the data plane.
    pub rng: Arc<dyn Rng>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
    /// The public keys that verify access tokens, parsed at start.
    pub keys: JwtKeySet,
    /// The discovery of the upstream endpoints and the zone of this pod.
    pub endpoints: EndpointAdapters,
    /// The reads of the state topic and the published snapshot.
    pub policy: PolicyAdapters,
    /// The recorder of the access log and the thread that writes it.
    pub access_log: AccessLogAdapters,
}

/// The adapters of the gateway cannot be wired.
#[derive(Debug, thiserror::Error)]
pub enum GatewayAdapterError {
    /// The key file cannot be read or parsed.
    #[error(transparent)]
    Keys(#[from] JwtKeyFileError),
    /// The endpoint discovery cannot be set up.
    #[error(transparent)]
    Endpoints(#[from] EndpointSetupError),
    /// The thread of the access log writer cannot be started.
    #[error("the access log writer cannot be started")]
    AccessLog(#[source] std::io::Error),
}

impl GatewayAdapters {
    /// Wires the production adapters: the random source is seeded from the operating system, the
    /// key file is parsed now, so that a gateway that cannot verify a token does not start, and the
    /// endpoint discovery is set up the same way.
    ///
    /// # Errors
    ///
    /// Returns the error of reading or parsing `JWT_PUBLIC_KEYS_FILE` or of setting up the
    /// endpoint discovery.
    pub fn from_config(config: &GatewayConfig) -> Result<Self, GatewayAdapterError> {
        let keys = JwtKeySet::load(&config.tokens.public_keys_file)?;
        let endpoints = EndpointAdapters::from_config(config)?;
        let rng: Arc<dyn Rng> = Arc::new(SeededRng::from_os());
        let readiness = ReadinessAdapters::from_config(
            config,
            &endpoints.directory,
            endpoints::peers_target(config),
            Arc::clone(&rng),
        );
        let policy = PolicyAdapters::from_config(config).comparing(readiness);
        policy.status.mark_keys_parsed();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let access_log = AccessLogAdapters::to_production(
            &config.access_log,
            &config.audit_lane,
            config.app_env,
            Arc::clone(&rng),
            Arc::clone(&clock),
        )
        .map_err(GatewayAdapterError::AccessLog)?;
        Ok(Self {
            rng,
            clock,
            keys,
            endpoints,
            policy,
            access_log,
        })
    }
}

impl std::fmt::Debug for GatewayAdapters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayAdapters")
            .field("rng", &self.rng)
            .field("clock", &self.clock)
            .field("endpoints", &self.endpoints)
            .field("policy", &self.policy)
            .field("access_log", &self.access_log)
            .finish_non_exhaustive()
    }
}

/// The per-replica tasks of the gateway: the `EndpointWatcher`, when there is a Service to watch.
///
/// `shutdown` is the stop flag of the service: tasks end when it is set.
#[must_use]
pub fn start_tasks(adapters: &GatewayAdapters, shutdown: watch::Receiver<bool>) -> TaskSupervisor {
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, shutdown);
    let endpoints = &adapters.endpoints;
    if !endpoints.targets.is_empty() {
        let watcher = EndpointWatcher::new(
            Arc::clone(&endpoints.watch),
            Arc::clone(&endpoints.directory),
            endpoints.targets.clone(),
            WatcherSettings::default(),
        );
        supervisor.spawn(EndpointWatcher::name(), move |stopping| {
            watcher.run(stopping)
        });
    }
    supervisor
}

#[cfg(test)]
mod tests;
