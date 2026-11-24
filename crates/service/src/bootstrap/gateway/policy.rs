//! The policy of the gateway: the adapters that read the state topic and publish the snapshot,
//! and the task that bootstraps the pod (FR-71, NFR-28, NFR-37).
//!
//! The pod rebuilds the complete policy from the state topic under the principal
//! `iam-gateway-bootstrap` and publishes it through the apply thread; PostgreSQL never takes part.
//! After the bootstrap the pod follows the topic in order under the principal `iam-gateway`
//! (Story 9.4): the raw batches go to the apply thread, which checks the digest of each version
//! before it publishes it. Any fault of the log fences the tail: the pod keeps its last verified
//! snapshot and rebootstraps after a random delay between 0 and `FRESHNESS_READY_BOUND`. A tail
//! task that dies ends the process. The apply thread also checks the derived structures against the
//! raw records (Story 9.6): a mismatch withdraws the snapshot and the tail ends through the same
//! rebootstrap path. Before the first bootstrap the pod waits for the topic to pass
//! the configuration verdict under `KAFKA_CONFIG_GATES`. The task also records what the probes of
//! Story 9.7 read in the [`PodStatus`]: the gates passed, a bootstrap installed a verified snapshot
//! and a fenced pod is rebootstrapping.

use std::sync::Arc;

use std::time::Duration;

use iam_application::{
    BootstrapMachine, BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, DerivedStateChecker,
    FenceCause, FreshnessProber, PodStatus, ProofSink, TailApplier, TailEnd, TailMachine,
    TailPorts, TailProgress, rebootstrap_delay, run_bootstrap, run_tail,
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
use super::freshness::FreshnessAdapters;
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
    /// How often a group of shards is checked against the raw records
    /// (`DERIVED_STATE_CHECK_INTERVAL`).
    pub derived_check_interval: Duration,
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
    /// The proof of freshness and its probe; `None` leaves the pod without a proof (Story 9.5).
    pub freshness: Option<FreshnessAdapters>,
    /// What the probes read about the start of the pod (Story 9.7).
    pub status: Arc<PodStatus>,
}

impl PolicyAdapters {
    /// The production wiring: the Kafka connection of `config`, which carries the bootstrap
    /// principal, the tail under the principal `iam-gateway` and the boot clock of the host.
    /// Nothing is opened until the first read.
    #[must_use]
    pub fn from_config(config: &GatewayConfig) -> Self {
        let boot_clock: Arc<dyn BootClock> = Arc::new(LinuxBootClock);
        let freshness = FreshnessAdapters::from_config(config, Arc::clone(&boot_clock));
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
                derived_check_interval: config.derived_state_check_interval,
            },
        };
        Self::with(
            Arc::new(KrafkaPolicyLogTail::bootstrap(config.kafka.clone())),
            boot_clock,
        )
        .following(tail)
        .proving(freshness)
    }

    /// The same wiring with the proof of freshness.
    #[must_use]
    pub fn proving(mut self, freshness: FreshnessAdapters) -> Self {
        self.freshness = Some(freshness);
        self
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
            freshness: None,
            status: Arc::new(PodStatus::new()),
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
    start_policy_with_thread(policy, tasks).map(|(death, _thread)| death)
}

/// Like [`start_policy`], and the handle to the apply thread comes back too: the tests that corrupt
/// a derived structure on the thread (Story 9.6) run their hook through it.
///
/// # Errors
///
/// Returns the error of starting the apply thread.
pub fn start_policy_with_thread(
    policy: &PolicyAdapters,
    tasks: &mut TaskSupervisor,
) -> std::io::Result<(oneshot::Receiver<()>, Arc<ApplyThread>)> {
    let builder = PolicySnapshotBuilder::new(
        policy.snapshot.clone(),
        Arc::clone(&policy.cell),
        PUBLISH_INTERVAL,
    );
    let checker = policy
        .tail
        .as_ref()
        .map(|tail| DerivedStateChecker::new(tail.settings.derived_check_interval));
    let freshness = policy.freshness.as_ref();
    let state = freshness.map(|adapters| Arc::clone(&adapters.state));
    let cell = Arc::clone(&policy.cell);
    let (thread, apply_death) = ApplyThread::spawn_proving(builder, cell, checker, state)?;
    let (tail_dead, tail_death) = oneshot::channel();
    let (dead, death) = oneshot::channel();
    tokio::spawn(merge_deaths(apply_death, tail_death, dead));
    let policy = policy.clone();
    let thread = Arc::new(thread);
    let handle = Arc::clone(&thread);
    if let Some(freshness) = policy.freshness.as_ref() {
        let sink: Arc<dyn ProofSink> = Arc::<ApplyThread>::clone(&thread);
        let prober = freshness.prober(Arc::<ArcSwapPolicySnapshot>::clone(&policy.cell), sink);
        tasks.spawn(FreshnessProber::name(), move |stopping| {
            prober.run(stopping)
        });
    }
    tasks.spawn(BOOTSTRAP_TASK, move |stopping| {
        policy_task(policy, thread, stopping, tail_dead)
    });
    Ok((death, handle))
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
    policy.status.mark_config_gates_passed();
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
    let progress: Arc<dyn TailProgress> = Arc::<ApplyThread>::clone(&thread);
    let ports = TailPorts {
        log: Arc::clone(&tail.log),
        applier,
        clock: Arc::clone(&tail.clock),
        progress,
    };
    loop {
        let machine = TailMachine::new(installed.tail_from, installed.read_to);
        let ended = run_tail(machine, &ports, tail.settings.retry_delay, &stopping).await;
        match ended {
            TailEnd::Stopped => return true,
            TailEnd::ApplierGone => return false,
            TailEnd::Fenced(cause) => {
                policy.status.begin_rebootstrap();
                log_fenced(&cause);
            }
        }
        match rebootstrap(&policy, &tail, &thread, &mut stopping).await {
            Some(next) => {
                installed = next;
                policy.status.end_rebootstrap();
            }
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
            policy.status.mark_bootstrapped();
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

/// What the bootstrap installed: the incomplete trailing version if any, and where the
/// tail starts.
struct Installed {
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
    thread.install(snapshot).await?;
    Ok(Installed {
        incomplete,
        tail_from,
        read_to,
    })
}

/// The metric event of the bootstrap that the publication does not emit, how long it took, and the
/// warning for an incomplete trailing version. The version, digest and derived hash of the pod are
/// reported by every publication of the builder.
fn report_started(installed: &Installed, elapsed: Duration) {
    log_bootstrap_seconds(elapsed.as_secs_f64());
    if let Some(trailing) = installed.incomplete {
        log_incomplete(trailing.value());
    }
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
