//! The policy of the gateway: the adapters that read the state topic and publish the snapshot,
//! and the task that bootstraps the pod (FR-71, NFR-28, NFR-37).
//!
//! The pod rebuilds the complete policy from the state topic under the principal
//! `iam-gateway-bootstrap` and publishes it through the apply thread; PostgreSQL never takes part.
//! After the bootstrap the pod follows the topic in order under the principal `iam-gateway`
//! (Story 9.4): the raw batches go to the apply thread, which checks the digest of each version
//! before it publishes it. Any fault of the log fences the tail: the pod keeps its last verified
//! snapshot and rebootstraps after a random delay between 0 and `FRESHNESS_READY_BOUND`. A tail
//! task that dies ends the process. Before the first bootstrap the pod waits for the topic to pass
//! the configuration verdict under `KAFKA_CONFIG_GATES`.

use std::sync::Arc;

use std::time::Duration;

use iam_application::{
    BootstrapMachine, BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, FenceCause, TailApplier,
    TailEnd, TailMachine, TailPorts, rebootstrap_delay, run_bootstrap, run_tail,
};
use iam_domain::{
    BootClock, KafkaTopicInspector, PolicyBootstrapLog, PolicyDigest, PolicyTailLog, Rng,
    StateRecordCodec,
};
use iam_infrastructure::{
    ArcSwapPolicySnapshot, JsonStateRecordCodec, KrafkaPolicyLogTail, KrafkaTopicInspector,
    LinuxBootClock, MatchitRouteTableCompiler, PUBLISH_INTERVAL, PolicySnapshotBuilder, SeededRng,
    Sha256PolicyDigest, SnapshotPorts,
};
use shared_domain::Clock;
use shared_infrastructure::clock::SystemClock;
use tokio::sync::{oneshot, watch};

use super::apply_thread::{ApplyError, ApplyThread};
use crate::bootstrap::TaskSupervisor;
use crate::config::GatewayConfig;

/// The name of the task that bootstraps the pod.
pub const BOOTSTRAP_TASK: &str = "policy-bootstrap";

/// How often the verdict of the state topic is evaluated again while it fails.
const TOPIC_RECHECK: Duration = Duration::from_secs(1);

/// The pauses and bounds of the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailSettings {
    /// The pause after a failed poll (`KAFKA_RETRY_DELAY`).
    pub retry_delay: Duration,
    /// The longest random delay before a fenced pod rebootstraps (`FRESHNESS_READY_BOUND`).
    pub ready_bound: Duration,
    /// The longest a fenced pod keeps its last verified snapshot (`FRESHNESS_HARD_BOUND`).
    pub hard_bound: Duration,
}

/// The ports of the tail and of the topic verdict.
#[derive(Debug, Clone)]
pub struct TailAdapters {
    /// Follows the state topic under the principal `iam-gateway`.
    pub log: Arc<dyn PolicyTailLog>,
    /// Judges the configuration of the state topic under `KAFKA_CONFIG_GATES`.
    pub inspector: Arc<dyn KafkaTopicInspector>,
    /// The wall clock, for the broker append-time check.
    pub clock: Arc<dyn Clock>,
    /// Draws the delay of a rebootstrap.
    pub rng: Arc<dyn Rng>,
    /// The pauses and bounds.
    pub settings: TailSettings,
}

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
    /// The tail and the topic verdict; `None` leaves the pod on the snapshot of its bootstrap.
    pub tail: Option<TailAdapters>,
}

impl PolicyAdapters {
    /// The production wiring: the Kafka connection of `config`, which carries the bootstrap
    /// principal, the tail under the principal `iam-gateway` and the boot clock of the host.
    /// Nothing is opened until the first read.
    #[must_use]
    pub fn from_config(config: &GatewayConfig) -> Self {
        let boot_clock: Arc<dyn BootClock> = Arc::new(LinuxBootClock);
        let tail = TailAdapters {
            log: Arc::new(KrafkaPolicyLogTail::tail(
                config.kafka_tail.clone(),
                config.kafka_fetch_max_wait,
            )),
            inspector: Arc::new(KrafkaTopicInspector::for_gateway(&config.kafka_tail)),
            clock: Arc::new(SystemClock),
            rng: Arc::new(SeededRng::from_os()),
            settings: TailSettings {
                retry_delay: config.kafka_tail.retry_delay,
                ready_bound: config.freshness_ready_bound,
                hard_bound: config.freshness_hard_bound,
            },
        };
        Self::with(
            Arc::new(KrafkaPolicyLogTail::bootstrap(config.kafka.clone())),
            boot_clock,
        )
        .following(tail)
    }

    /// The same wiring with the tail and the topic verdict.
    #[must_use]
    pub fn following(mut self, tail: TailAdapters) -> Self {
        self.tail = Some(tail);
        self
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
            tail: None,
        }
    }
}

/// Starts the apply thread and the task that bootstraps and then tails the pod; the channel
/// resolves when the apply thread or the tail dies, which ends the gateway.
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
    let (thread, apply_death) = ApplyThread::spawn(builder, Arc::clone(&policy.cell))?;
    let (tail_dead, tail_death) = oneshot::channel();
    let (dead, death) = oneshot::channel();
    tokio::spawn(merge_deaths(apply_death, tail_death, dead));
    let policy = policy.clone();
    let thread = Arc::new(thread);
    tasks.spawn(BOOTSTRAP_TASK, move |stopping| {
        policy_task(policy, thread, stopping, tail_dead)
    });
    Ok(death)
}

/// Sends the one death notice when either side dies; two clean endings send none.
async fn merge_deaths(
    apply: oneshot::Receiver<()>,
    tail: oneshot::Receiver<()>,
    dead: oneshot::Sender<()>,
) {
    tokio::select! {
        Ok(()) = apply => dead.send(()).unwrap_or_default(),
        Ok(()) = tail => dead.send(()).unwrap_or_default(),
        else => {}
    }
}

/// Bootstraps the pod, follows the topic when the tail is wired and keeps the apply thread alive
/// until the gateway stops.
async fn policy_task(
    policy: PolicyAdapters,
    thread: Arc<ApplyThread>,
    mut stopping: watch::Receiver<bool>,
    tail_dead: oneshot::Sender<()>,
) {
    if let Some(tail) = policy.tail.as_ref()
        && !topic_ready(tail, &mut stopping).await
    {
        return;
    }
    match (attempt(&policy, &thread).await, policy.tail.clone()) {
        (Some(installed), Some(tail)) => {
            if !follow(&policy, tail, &thread, installed, stopping).await {
                log_tail_died();
                tail_dead.send(()).unwrap_or_default();
            }
        }
        _ => drop(stopping.wait_for(|stopping| *stopping).await),
    }
}

/// Waits until the topic passes its configuration verdict; `false` when the gateway stops first.
/// A topic that breaks a rule, or a cluster that cannot be asked, keeps the pod from starting.
async fn topic_ready(tail: &TailAdapters, stopping: &mut watch::Receiver<bool>) -> bool {
    loop {
        match tail.inspector.inspect().await {
            Ok(verdict) if verdict.passed() => return true,
            Ok(verdict) => log_topic_broken(&verdict.describe()),
            Err(error) => log_topic_unreadable(&error),
        }
        if paused(TOPIC_RECHECK, stopping).await {
            return false;
        }
    }
}

/// Waits `delay`; whether the gateway is stopping.
async fn paused(delay: Duration, stopping: &mut watch::Receiver<bool>) -> bool {
    let stopped = tokio::select! {
        () = tokio::time::sleep(delay) => false,
        changed = stopping.wait_for(|stopping| *stopping) => {
            drop(changed);
            true
        }
    };
    stopped || *stopping.borrow()
}

/// Runs the tail as a task of its own, so that a panic in it is seen here and ends the process
/// through the death channel; the apply thread stays alive until the tail ends. `true` when the
/// gateway stopped, `false` when the tail died.
async fn follow(
    policy: &PolicyAdapters,
    tail: TailAdapters,
    thread: &Arc<ApplyThread>,
    installed: Installed,
    stopping: watch::Receiver<bool>,
) -> bool {
    let tail_task = tokio::spawn(tail_loop(
        policy.clone(),
        tail,
        Arc::clone(thread),
        installed,
        stopping,
    ));
    matches!(tail_task.await, Ok(true))
}

/// Follows the topic, and after every fence rebootstraps and follows again. `true` when the
/// gateway stopped, `false` when the apply thread ended.
async fn tail_loop(
    policy: PolicyAdapters,
    tail: TailAdapters,
    thread: Arc<ApplyThread>,
    mut installed: Installed,
    mut stopping: watch::Receiver<bool>,
) -> bool {
    let concrete: Arc<ApplyThread> = Arc::clone(&thread);
    let applier: Arc<dyn TailApplier> = concrete;
    let ports = TailPorts {
        log: Arc::clone(&tail.log),
        applier,
        clock: Arc::clone(&tail.clock),
    };
    loop {
        let machine = TailMachine::new(installed.tail_from, installed.read_to);
        let ended = run_tail(machine, &ports, tail.settings.retry_delay, &stopping).await;
        match ended {
            TailEnd::Stopped => return true,
            TailEnd::ApplierGone => return false,
            TailEnd::Fenced(cause) => log_fenced(&cause),
        }
        match rebootstrap(&policy, &tail, &thread, &mut stopping).await {
            Some(next) => installed = next,
            None => return true,
        }
    }
}

/// Waits a random delay, then bootstraps again; a failed bootstrap waits and tries again, and the
/// last verified snapshot keeps serving meanwhile. `None` when the gateway stops first.
async fn rebootstrap(
    policy: &PolicyAdapters,
    tail: &TailAdapters,
    thread: &ApplyThread,
    stopping: &mut watch::Receiver<bool>,
) -> Option<Installed> {
    loop {
        let delay = rebootstrap_delay(tail.rng.as_ref(), tail.settings.ready_bound);
        log_rebootstrap_delay(delay);
        if paused(delay, stopping).await {
            return None;
        }
        if let Some(installed) = attempt(policy, thread).await {
            return Some(installed);
        }
    }
}

/// One bootstrap: it either publishes a snapshot, or leaves the pod as it was.
async fn attempt(policy: &PolicyAdapters, thread: &ApplyThread) -> Option<Installed> {
    let started = policy.boot_clock.now();
    match bootstrap(policy, thread).await {
        Ok(installed) => {
            report_started(
                &installed,
                policy.boot_clock.now().saturating_since(started),
            );
            Some(installed)
        }
        Err(error) => {
            log_not_started(&error);
            None
        }
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

/// What the bootstrap installed: the version, the incomplete trailing version if any, and where the
/// tail starts.
struct Installed {
    version: iam_domain::PolicyVersion,
    incomplete: Option<iam_domain::PolicyVersion>,
    tail_from: i64,
    read_to: i64,
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
    let (incomplete, tail_from, read_to) =
        (snapshot.incomplete, snapshot.tail_from, snapshot.read_to);
    let version = thread.install(snapshot).await?;
    Ok(Installed {
        version,
        incomplete,
        tail_from,
        read_to,
    })
}

/// The two metric events of the bootstrap: the version the pod published and how long it took.
fn report_started(installed: &Installed, elapsed: Duration) {
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

fn log_topic_broken(violations: &str) {
    tracing::error!(
        violations,
        "the state topic breaks a configuration rule; the gateway does not start until it passes"
    );
}

fn log_topic_unreadable(error: &iam_domain::KafkaInspectionError) {
    tracing::error!(%error, "the state topic cannot be inspected; the gateway does not start yet");
}

fn log_fenced(cause: &FenceCause) {
    tracing::error!(
        metric = "policy_fenced",
        %cause,
        "the policy tail fenced itself; the pod keeps its last verified snapshot and rebootstraps"
    );
}

fn log_rebootstrap_delay(delay: Duration) {
    let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    tracing::info!(delay_ms, "the fenced pod rebootstraps after a random delay");
}

fn log_tail_died() {
    tracing::error!("the policy tail task died; the gateway exits");
}

#[cfg(test)]
mod tests;
