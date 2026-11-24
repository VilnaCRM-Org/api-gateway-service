//! The apply thread of the gateway (FR-71, NFR-16): the one OS thread that owns the
//! [`PolicySnapshotBuilder`].
//!
//! Decoding and applying a version is CPU work that must not run on a tokio worker, so the builder
//! lives on a dedicated thread and the rest of the process talks to it through a channel. The
//! thread also frees the retired snapshots when their strong count reaches 1 (deferred
//! reclamation), so a request task that drops the last reference to a replaced generation never
//! runs its destructor.
//!
//! A thread that ends without being asked to, by a panic or otherwise, sends a death notice; the
//! gateway then exits with a failure code, because a pod that cannot apply the log must not serve
//! on a snapshot that no longer moves.

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use iam_application::BootstrapSnapshot;
use iam_domain::PolicyVersion;
use iam_infrastructure::{
    ArcSwapPolicySnapshot, PolicySnapshotBuilder, RawEntry, SnapshotBuildError,
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

enum Command {
    Install(Box<Install>),
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

/// A handle to the apply thread.
#[derive(Debug)]
pub struct ApplyThread {
    commands: mpsc::Sender<Command>,
    handle: Option<JoinHandle<()>>,
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
        let (commands, received) = mpsc::channel();
        let (dead, death) = oneshot::channel();
        let handle = std::thread::Builder::new()
            .name("policy-apply".to_owned())
            .spawn(move || run(builder, &cell, &received, dead))?;
        let thread = Self {
            commands,
            handle: Some(handle),
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
    dead: oneshot::Sender<()>,
) {
    let mut notice = DeathNotice {
        sender: Some(dead),
        clean: false,
    };
    serve(builder, cell, commands);
    notice.clean = true;
}

/// The loop of the thread: commands, and between them the ticks that publish and reclaim.
fn serve(
    mut builder: PolicySnapshotBuilder,
    cell: &ArcSwapPolicySnapshot,
    commands: &mpsc::Receiver<Command>,
) {
    loop {
        match commands.recv_timeout(RECLAIM_INTERVAL) {
            Ok(Command::Install(install)) => answer(&mut builder, *install),
            Ok(Command::Run(hook)) => hook(&mut builder),
            Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                builder.tick();
            }
        }
        reclaim(cell);
    }
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

fn answer(builder: &mut PolicySnapshotBuilder, install: Install) {
    let applied = apply(builder, install.snapshot);
    install.reply.send(applied).unwrap_or_default();
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

#[cfg(test)]
mod tests;
