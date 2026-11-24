//! The policy of the gateway: the adapters that read the state topic and publish the snapshot,
//! and the task that bootstraps the pod (FR-71, NFR-28, NFR-37).
//!
//! The pod rebuilds the complete policy from the state topic under the principal
//! `iam-gateway-bootstrap` and publishes it through the apply thread; PostgreSQL never takes part.
//! Until Story 9.4 the pod does not tail the topic after the bootstrap.

use std::sync::Arc;

use iam_application::{
    BootstrapMachine, BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, run_bootstrap,
};
use iam_domain::{BootClock, PolicyBootstrapLog, PolicyDigest, StateRecordCodec};
use iam_infrastructure::{
    ArcSwapPolicySnapshot, JsonStateRecordCodec, KrafkaPolicyLogTail, LinuxBootClock,
    MatchitRouteTableCompiler, PUBLISH_INTERVAL, PolicySnapshotBuilder, Sha256PolicyDigest,
    SnapshotPorts,
};
use tokio::sync::{oneshot, watch};

use super::apply_thread::{ApplyError, ApplyThread};
use crate::bootstrap::TaskSupervisor;
use crate::config::GatewayConfig;

/// The name of the task that bootstraps the pod.
pub const BOOTSTRAP_TASK: &str = "policy-bootstrap";

/// What the policy of the gateway needs from the composition root.
#[derive(Debug, Clone)]
pub struct PolicyAdapters {
    /// The published snapshot; it queues the replaced generations for the apply thread.
    pub cell: Arc<ArcSwapPolicySnapshot>,
    /// The reads of the state topic under the bootstrap principal.
    pub log: Arc<dyn PolicyBootstrapLog>,
    /// The ports of the pure bootstrap judgement.
    pub bootstrap: BootstrapPorts,
    /// The ports of the snapshot builder.
    pub snapshot: SnapshotPorts,
    /// Measures `policy_bootstrap_seconds`.
    pub boot_clock: Arc<dyn BootClock>,
}

impl PolicyAdapters {
    /// The production wiring: the Kafka connection of `config`, which carries the bootstrap
    /// principal, and the boot clock of the host. Nothing is opened until the first read.
    #[must_use]
    pub fn from_config(config: &GatewayConfig) -> Self {
        let boot_clock: Arc<dyn BootClock> = Arc::new(LinuxBootClock);
        Self::with(
            Arc::new(KrafkaPolicyLogTail::bootstrap(config.kafka.clone())),
            boot_clock,
        )
    }

    /// The wiring over `log` and `boot_clock`; the codec, the digest and the route compiler are
    /// those of production.
    #[must_use]
    pub fn with(log: Arc<dyn PolicyBootstrapLog>, boot_clock: Arc<dyn BootClock>) -> Self {
        let codec: Arc<dyn StateRecordCodec> = Arc::new(JsonStateRecordCodec);
        let digest: Arc<dyn PolicyDigest> = Arc::new(Sha256PolicyDigest);
        Self {
            cell: Arc::new(ArcSwapPolicySnapshot::deferred()),
            log,
            bootstrap: BootstrapPorts {
                codec: Arc::clone(&codec),
                digest: Arc::clone(&digest),
            },
            snapshot: SnapshotPorts {
                codec,
                digest,
                compiler: Arc::new(MatchitRouteTableCompiler),
                boot_clock: Arc::clone(&boot_clock),
            },
            boot_clock,
        }
    }
}

/// Starts the apply thread and the task that bootstraps the pod; the channel resolves when the
/// apply thread dies, which ends the gateway.
///
/// # Errors
///
/// Returns the error of starting the apply thread.
pub fn start_policy(
    policy: &PolicyAdapters,
    tasks: &mut TaskSupervisor,
) -> std::io::Result<oneshot::Receiver<()>> {
    let builder = PolicySnapshotBuilder::new(
        policy.snapshot.clone(),
        Arc::clone(&policy.cell),
        PUBLISH_INTERVAL,
    );
    let (thread, death) = ApplyThread::spawn(builder, Arc::clone(&policy.cell))?;
    let policy = policy.clone();
    tasks.spawn(BOOTSTRAP_TASK, move |stopping| {
        bootstrap_task(policy, thread, stopping)
    });
    Ok(death)
}

/// Bootstraps the pod, then keeps the apply thread alive until the gateway stops.
async fn bootstrap_task(
    policy: PolicyAdapters,
    thread: ApplyThread,
    mut stopping: watch::Receiver<bool>,
) {
    attempt(&policy, &thread).await;
    drop(stopping.wait_for(|stopping| *stopping).await);
    drop(thread);
}

/// One bootstrap: it either publishes the first snapshot or leaves the pod not started.
async fn attempt(policy: &PolicyAdapters, thread: &ApplyThread) {
    let started = policy.boot_clock.now();
    match bootstrap(policy, thread).await {
        Ok(installed) => {
            report_started(
                &installed,
                policy.boot_clock.now().saturating_since(started),
            );
        }
        Err(error) => log_not_started(&error),
    }
}

/// Why the pod did not start.
#[derive(Debug, thiserror::Error)]
enum StartError {
    #[error("the bootstrap failed: {0}")]
    Bootstrap(#[from] iam_application::BootstrapFailure),
    #[error("the state could not be installed: {0}")]
    Install(#[from] ApplyError),
}

/// What the bootstrap installed: the version and the incomplete trailing version, if any.
struct Installed {
    version: iam_domain::PolicyVersion,
    incomplete: Option<iam_domain::PolicyVersion>,
}

async fn bootstrap(policy: &PolicyAdapters, thread: &ApplyThread) -> Result<Installed, StartError> {
    let machine = BootstrapMachine::new(policy.bootstrap.clone());
    match run_bootstrap(machine, policy.log.as_ref()).await {
        BootstrapOutcome::Started(snapshot) => install(thread, snapshot).await,
        BootstrapOutcome::NotStarted(failure) => Err(failure.into()),
    }
}

async fn install(
    thread: &ApplyThread,
    snapshot: BootstrapSnapshot,
) -> Result<Installed, StartError> {
    let incomplete = snapshot.incomplete;
    let version = thread.install(snapshot).await?;
    Ok(Installed {
        version,
        incomplete,
    })
}

/// The two metric events of the bootstrap: the version the pod published and how long it took.
fn report_started(installed: &Installed, elapsed: std::time::Duration) {
    log_applied_version(installed.version.value());
    log_bootstrap_seconds(elapsed.as_secs_f64());
    if let Some(trailing) = installed.incomplete {
        log_incomplete(trailing.value());
    }
}

fn log_applied_version(version: i64) {
    tracing::info!(
        metric = "policy_applied_version",
        version,
        "policy snapshot published"
    );
}

fn log_bootstrap_seconds(seconds: f64) {
    tracing::info!(
        metric = "policy_bootstrap_seconds",
        seconds,
        "gateway bootstrap finished"
    );
}

fn log_incomplete(trailing: i64) {
    tracing::warn!(
        trailing,
        "the state topic ends in a version that is not complete; the pod serves the version before it"
    );
}

fn log_not_started(error: &StartError) {
    tracing::error!(%error, "the gateway stays not started");
}

#[cfg(test)]
mod tests;
