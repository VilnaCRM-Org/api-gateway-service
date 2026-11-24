//! The apply thread of the gateway (FR-71, NFR-16): the one OS thread that owns the
//! [`PolicySnapshotBuilder`].
//!
//! Decoding and applying a version is CPU work that must not run on a tokio worker, so the builder
//! lives on a dedicated thread and the rest of the process talks to it through a channel. The
//! thread also frees the retired snapshots when their strong count reaches 1 (deferred
//! reclamation), so a request task that drops the last reference to a replaced generation never
//! runs its destructor.
//!
//! The thread also runs the [`DerivedStateChecker`] (Story 9.6): every check interval it rebuilds
//! the derived structures of a sixteenth of the shards from the raw records and compares them with
//! the incremental ones. A mismatch means the published snapshot is wrong, so the thread withdraws
//! it at once: readers find no snapshot and answer `iam_stale`, nothing is published again, and the
//! tail ends and rebootstraps through the fault the thread reports. A successful install lifts it.
//!
//! A thread that ends without being asked to, by a panic or otherwise, sends a death notice; the
//! gateway then exits with a failure code, because a pod that cannot apply the log must not serve
//! on a snapshot that no longer moves.

mod proofs;

use self::proofs::Proofs;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use iam_application::{
    ApplyResult, BootstrapSnapshot, CheckOutcome, DerivedStateChecker, FenceCause, TailApplier,
};
use iam_application::{FreshnessState, ProofSink, TailProgress};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{DerivedMismatch, FenceVerdict, FramedRecord, PolicyVersion};
use iam_infrastructure::{
    ApplyOutcome, ArcSwapPolicySnapshot, PolicySnapshotBuilder, RawEntry, SnapshotBuildError,
};
use tokio::sync::oneshot;

/// How long the thread waits for a command before it ticks the builder and frees what it can.
pub const RECLAIM_INTERVAL: Duration = Duration::from_millis(50);

/// A closure that runs on the apply thread with the builder: the hook of the tests that drive the
/// thread.
type Hook = Box<dyn FnOnce(&mut PolicySnapshotBuilder) + Send>;

/// A state to install, with the channel that carries the answer back.
struct Install {
    snapshot: BootstrapSnapshot,
    reply: oneshot::Sender<Result<PolicyVersion, SnapshotBuildError>>,
}

/// A raw batch of the tail to apply, with the channel that carries the answer back.
struct Batch {
    records: Vec<FramedRecord>,
    reply: oneshot::Sender<ApplyResult>,
}

enum Command {
    Install(Box<Install>),
    Apply(Batch),
    Proof(FreshnessProof),
    CaughtUp { position: i64, high: i64 },
    Run(Hook),
    Stop,
}

/// The apply thread cannot do what it was asked.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The thread ended.
    #[error("the apply thread ended")]
    Gone,
    /// The builder refused the state.
    #[error("the policy state was refused")]
    Refused(#[from] SnapshotBuildError),
}

/// Sends the death notice when the thread ends without a clean stop, a panic included.
struct DeathNotice {
    sender: Option<oneshot::Sender<()>>,
    clean: bool,
}

impl Drop for DeathNotice {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take().filter(|_sender| !self.clean) {
            sender.send(()).unwrap_or_default();
        }
    }
}

/// The fault that the check found, waiting for the tail to take it.
type Fault = Arc<Mutex<Option<FenceCause>>>;

/// A handle to the apply thread.
#[derive(Debug)]
pub struct ApplyThread {
    commands: mpsc::Sender<Command>,
    handle: Option<JoinHandle<()>>,
    fault: Fault,
}

impl ApplyThread {
    /// Starts the thread over `builder`, which publishes into `cell`; the cell must be
    /// [deferred](ArcSwapPolicySnapshot::deferred) for the thread to reclaim anything. With the
    /// handle comes the channel that resolves with `Ok` when the thread dies.
    ///
    /// # Errors
    ///
    /// Returns the error of starting the thread.
    pub fn spawn(
        builder: PolicySnapshotBuilder,
        cell: Arc<ArcSwapPolicySnapshot>,
    ) -> std::io::Result<(Self, oneshot::Receiver<()>)> {
        Self::spawn_checked(builder, cell, None)
    }

    /// Like [`spawn`](Self::spawn), and the thread runs `checker` against the builder: a mismatch
    /// withdraws the snapshot and is reported through [`TailApplier::fault`].
    ///
    /// # Errors
    ///
    /// Returns the error of starting the thread.
    pub fn spawn_checked(
        builder: PolicySnapshotBuilder,
        cell: Arc<ArcSwapPolicySnapshot>,
        checker: Option<DerivedStateChecker>,
    ) -> std::io::Result<(Self, oneshot::Receiver<()>)> {
        Self::spawn_proving(builder, cell, checker, None)
    }

    /// Like [`spawn_checked`](Self::spawn_checked), and the thread attaches the proofs of
    /// freshness it is offered to the published snapshot, into `freshness` (Story 9.5).
    ///
    /// # Errors
    ///
    /// Returns the error of starting the thread.
    pub fn spawn_proving(
        builder: PolicySnapshotBuilder,
        cell: Arc<ArcSwapPolicySnapshot>,
        checker: Option<DerivedStateChecker>,
        freshness: Option<Arc<FreshnessState>>,
    ) -> std::io::Result<(Self, oneshot::Receiver<()>)> {
        let (commands, received) = mpsc::channel();
        let (dead, death) = oneshot::channel();
        let fault = Fault::default();
        let guard = Guard {
            checker,
            fault: Arc::clone(&fault),
            fenced: None,
            proofs: Proofs::new(freshness),
        };
        let handle = std::thread::Builder::new()
            .name("policy-apply".to_owned())
            .spawn(move || run(builder, &cell, &received, (guard, dead)))?;
        let thread = Self {
            commands,
            handle: Some(handle),
            fault,
        };
        Ok((thread, death))
    }

    /// Replaces the state with the one the bootstrap read and publishes it; the version applied.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Gone`] when the thread ended and [`ApplyError::Refused`] when the builder
    /// refuses the state; nothing is published then.
    pub async fn install(&self, snapshot: BootstrapSnapshot) -> Result<PolicyVersion, ApplyError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Install(Box::new(Install { snapshot, reply })))
            .map_err(|_gone| ApplyError::Gone)?;
        let applied = answer.await.map_err(|_gone| ApplyError::Gone)?;
        Ok(applied?)
    }

    /// Hands a raw batch of the tail to the thread: it assembles the versions, checks the digest of
    /// each complete one before it publishes it and stops at the first fault of the log.
    pub async fn apply_batch(&self, records: Vec<FramedRecord>) -> ApplyResult {
        let (reply, answer) = oneshot::channel();
        let sent = self.commands.send(Command::Apply(Batch { records, reply }));
        match sent {
            Ok(()) => answer.await.unwrap_or(ApplyResult::Gone),
            Err(_gone) => ApplyResult::Gone,
        }
    }

    /// Runs `hook` on the apply thread with the builder. It exists for the tests that drive the
    /// thread, which inject a panic or read the identity of the thread through it.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Gone`] when the thread ended.
    pub fn run_on_thread<F>(&self, hook: F) -> Result<(), ApplyError>
    where
        F: FnOnce(&mut PolicySnapshotBuilder) + Send + 'static,
    {
        self.commands
            .send(Command::Run(Box::new(hook)))
            .map_err(|_gone| ApplyError::Gone)
    }

    /// Asks the thread to end and waits for it; whether it ended without a panic.
    #[must_use]
    pub fn stop(mut self) -> bool {
        self.commands.send(Command::Stop).unwrap_or_default();
        self.handle
            .take()
            .is_some_and(|handle| handle.join().is_ok())
    }
}

/// The body of the thread: the loop, and the death notice when it ends without a clean stop.
fn run(
    builder: PolicySnapshotBuilder,
    cell: &ArcSwapPolicySnapshot,
    commands: &mpsc::Receiver<Command>,
    (guard, dead): (Guard, oneshot::Sender<()>),
) {
    let mut notice = DeathNotice {
        sender: Some(dead),
        clean: false,
    };
    serve(builder, cell, commands, guard);
    notice.clean = true;
}

/// The loop of the thread: commands, and between them the ticks that publish and reclaim.
fn serve(
    mut builder: PolicySnapshotBuilder,
    cell: &ArcSwapPolicySnapshot,
    commands: &mpsc::Receiver<Command>,
    mut guard: Guard,
) {
    loop {
        match commands.recv_timeout(RECLAIM_INTERVAL) {
            Ok(Command::Install(install)) => answer(&mut builder, &mut guard, *install),
            Ok(Command::Apply(batch)) => answer_batch(&mut builder, &mut guard, batch),
            Ok(Command::Proof(proof)) => guard.proofs.offer(proof),
            Ok(Command::CaughtUp { position, high }) => guard.proofs.caught_up(position, high),
            Ok(Command::Run(hook)) => hook(&mut builder),
            Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => guard.tick(&mut builder),
        }
        guard.check(&mut builder, cell);
        guard.proofs.attach(&builder, cell);
        reclaim(cell);
    }
}

/// The derived-state check of the thread and the fence it raises.
struct Guard {
    checker: Option<DerivedStateChecker>,
    fault: Fault,
    /// The mismatch that withdrew the snapshot; set until a state is installed.
    fenced: Option<FenceCause>,
    /// The proofs of freshness that wait for a snapshot that covers them (Story 9.5).
    proofs: Proofs,
}

impl Guard {
    /// Publishes what is due, unless the state is known to be wrong.
    fn tick(&self, builder: &mut PolicySnapshotBuilder) {
        if self.fenced.is_none() {
            builder.tick();
        }
    }

    /// Runs the check that is due. A mismatch withdraws the published snapshot, so that no request
    /// is allowed on it, and hands the fault to the tail.
    fn check(&mut self, builder: &mut PolicySnapshotBuilder, cell: &ArcSwapPolicySnapshot) {
        let Some(checker) = self.checker.as_mut() else {
            return;
        };
        let outcome = checker.run(builder.now(), builder);
        match outcome {
            CheckOutcome::NotDue => {}
            CheckOutcome::Passed { group, shards } => log_checked(group, shards),
            CheckOutcome::Mismatch(mismatch) => self.fence(cell, &mismatch),
        }
    }

    fn fence(&mut self, cell: &ArcSwapPolicySnapshot, mismatch: &DerivedMismatch) {
        log_mismatch(mismatch);
        let cause = FenceCause::DerivedMismatch {
            shard: mismatch.shard,
        };
        *self.fault.lock().unwrap_or_else(PoisonError::into_inner) = Some(cause.clone());
        self.fenced = Some(cause);
        cell.clear();
    }

    /// The state was replaced by a verified one: the checks and the publications resume.
    fn lift(&mut self) {
        self.fenced = None;
        self.fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(checker) = self.checker.as_mut() {
            checker.restart();
        }
    }
}

fn log_checked(group: usize, shards: usize) {
    tracing::debug!(group, shards, "derived structures match the raw records");
}

fn log_mismatch(mismatch: &DerivedMismatch) {
    let (rebuilt, held) = (mismatch.rebuilt.to_hex(), mismatch.held.to_hex());
    tracing::error!(
        metric = "policy_derived_mismatch",
        shard = mismatch.shard,
        rebuilt = %rebuilt,
        held = %held,
        "a derived structure differs from the raw records; the pod stops allowing and rebootstraps"
    );
}

/// Frees the retired snapshots that no request holds, on this thread.
fn reclaim(cell: &ArcSwapPolicySnapshot) {
    let freed = cell.reclaim();
    if freed > 0 {
        log_reclaimed(freed);
    }
}

fn log_reclaimed(freed: usize) {
    tracing::debug!(freed, "retired policy snapshots freed on the apply thread");
}

fn answer(builder: &mut PolicySnapshotBuilder, guard: &mut Guard, install: Install) {
    let tail_from = install.snapshot.tail_from;
    let applied = apply(builder, install.snapshot);
    if applied.is_ok() {
        guard.lift();
        guard.proofs.installed(tail_from);
    }
    install.reply.send(applied).unwrap_or_default();
}

/// A thread whose state failed the check applies nothing: the batch is answered with the fault.
fn answer_batch(builder: &mut PolicySnapshotBuilder, guard: &mut Guard, batch: Batch) {
    let result = match &guard.fenced {
        Some(cause) => ApplyResult::Fenced(cause.clone()),
        None => apply_batch(builder, &mut guard.proofs, batch.records),
    };
    batch.reply.send(result).unwrap_or_default();
}

/// Offers the records of a batch to the builder in order. The first record that shows a fault of
/// the log ends the batch: nothing after it is applied, and a version whose digest does not match
/// its head was never published. Whatever was applied before the fault is published.
fn apply_batch(
    builder: &mut PolicySnapshotBuilder,
    proofs: &mut Proofs,
    records: Vec<FramedRecord>,
) -> ApplyResult {
    let mut result = ApplyResult::Applied;
    for framed in records {
        let offset = framed.offset;
        let outcome = builder.offer(framed.record);
        proofs.record(offset, &outcome);
        if let Some(cause) = fence_cause(&outcome, offset) {
            result = ApplyResult::Fenced(cause);
            break;
        }
    }
    builder.tick();
    result
}

/// The fault of the log that an outcome shows; `None` for an outcome that is progress, a repeat or
/// a version that is not complete yet.
fn fence_cause(outcome: &ApplyOutcome, offset: i64) -> Option<FenceCause> {
    match outcome {
        ApplyOutcome::Ignored(_)
        | ApplyOutcome::Duplicate
        | ApplyOutcome::Pending { .. }
        | ApplyOutcome::Applied { .. } => None,
        ApplyOutcome::Malformed => Some(FenceCause::Malformed { offset }),
        ApplyOutcome::Gap { expected } => Some(FenceCause::Gap {
            expected: expected.value(),
        }),
        ApplyOutcome::Fenced(FenceVerdict::ConflictingContent) => {
            Some(FenceCause::ConflictingContent)
        }
        ApplyOutcome::Fenced(FenceVerdict::LowerLogEpoch) => Some(FenceCause::LowerLogEpoch),
        ApplyOutcome::Rejected(SnapshotBuildError::DigestMismatch { version, .. }) => {
            Some(FenceCause::DigestMismatch {
                version: version.value(),
            })
        }
        ApplyOutcome::Rejected(error) => Some(FenceCause::Unappliable(error.to_string())),
    }
}

/// Applies the state of the bootstrap through the builder, which refuses a state whose digest is
/// not the digest of its head.
fn apply(
    builder: &mut PolicySnapshotBuilder,
    snapshot: BootstrapSnapshot,
) -> Result<PolicyVersion, SnapshotBuildError> {
    let entries: Vec<RawEntry> = snapshot
        .entries
        .into_iter()
        .map(|entry| RawEntry {
            key: entry.key,
            version: entry.version,
            payload: entry.payload,
        })
        .collect();
    builder.rebuild_verified(
        &entries,
        snapshot.version,
        (snapshot.log_epoch, snapshot.digest),
    )?;
    Ok(snapshot.version)
}

#[async_trait::async_trait]
impl TailApplier for ApplyThread {
    async fn apply(&self, records: Vec<FramedRecord>) -> ApplyResult {
        self.apply_batch(records).await
    }

    fn fault(&self) -> Option<FenceCause> {
        self.fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl ProofSink for ApplyThread {
    fn offer(&self, proof: FreshnessProof) {
        self.commands
            .send(Command::Proof(proof))
            .unwrap_or_default();
    }
}

impl TailProgress for ApplyThread {
    fn caught_up(&self, position: i64, high: i64) {
        self.commands
            .send(Command::CaughtUp { position, high })
            .unwrap_or_default();
    }
}

#[cfg(test)]
mod tests;
