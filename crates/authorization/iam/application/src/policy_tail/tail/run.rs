//! The driver of the tail machine: it executes the actions against the topic and the apply thread.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{FramedRecord, PolicyLogTailError, PolicyTailLog};
use shared_domain::Clock;
use tokio::sync::watch;

use super::{FenceCause, TailAction, TailInput, TailMachine};

/// What the apply thread did with a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// Every record was handled: applied, held for its version, or ignored as a repeat.
    Applied,
    /// A fault of the log; nothing of the faulty version was published.
    Fenced(FenceCause),
    /// The apply thread ended.
    Gone,
}

/// Applies raw batches; the apply thread behind it assembles and verifies the versions.
#[async_trait::async_trait]
pub trait TailApplier: std::fmt::Debug + Send + Sync {
    /// Applies `records`, in offset order.
    async fn apply(&self, records: Vec<FramedRecord>) -> ApplyResult;
}

/// The ports of the driver.
#[derive(Debug, Clone)]
pub struct TailPorts {
    /// Follows the topic.
    pub log: Arc<dyn PolicyTailLog>,
    /// Applies the batches.
    pub applier: Arc<dyn TailApplier>,
    /// The wall clock, for the append-time check.
    pub clock: Arc<dyn Clock>,
}

/// How the tail ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailEnd {
    /// The log cannot be trusted: rebootstrap.
    Fenced(FenceCause),
    /// The service is stopping.
    Stopped,
    /// The apply thread ended: the process must exit.
    ApplierGone,
}

/// What the actions of one step lead to.
enum Settled {
    End(TailEnd),
    Next(TailInput),
}

/// Runs `machine` until the log is fenced, the service stops or the apply thread ends. `retry` is
/// the pause after a failed poll. The connection is closed when the tail ends.
pub async fn run_tail(
    machine: TailMachine,
    ports: &TailPorts,
    retry: Duration,
    stopping: &watch::Receiver<bool>,
) -> TailEnd {
    let end = drive(machine, ports, retry, stopping).await;
    ports.log.close().await;
    end
}

async fn drive(
    mut machine: TailMachine,
    ports: &TailPorts,
    retry: Duration,
    stopping: &watch::Receiver<bool>,
) -> TailEnd {
    let mut input = TailInput::Start;
    loop {
        if *stopping.borrow() {
            return TailEnd::Stopped;
        }
        let (next, actions) = machine.step(input);
        machine = next;
        match settle(actions, ports, retry).await {
            Settled::End(end) => return end,
            Settled::Next(following) => input = following,
        }
    }
}

async fn settle(actions: Vec<TailAction>, ports: &TailPorts, retry: Duration) -> Settled {
    let mut following = None;
    for action in actions {
        match action {
            TailAction::Fence(cause) => return Settled::End(TailEnd::Fenced(cause)),
            TailAction::Backoff => tokio::time::sleep(retry).await,
            TailAction::Poll { position } => following = Some(poll(ports, position).await),
            TailAction::Apply(records) => {
                following = match apply(ports, records).await {
                    Ok(input) => Some(input),
                    Err(end) => return Settled::End(end),
                };
            }
        }
    }
    Settled::Next(following.unwrap_or_else(stalled))
}

/// A step that asks for nothing would loop for ever without a pause; it is a failed poll.
fn stalled() -> TailInput {
    TailInput::ReadFailed("the tail made no progress".to_owned())
}

async fn poll(ports: &TailPorts, position: i64) -> TailInput {
    match ports.log.poll(position).await {
        Ok(batch) => TailInput::Polled {
            batch,
            now_ms: now_ms(ports.clock.now()),
        },
        Err(error) => failed_poll(&error, position),
    }
}

fn failed_poll(error: &PolicyLogTailError, position: i64) -> TailInput {
    if let PolicyLogTailError::Malformed { offset } = error {
        return TailInput::Unreadable { offset: *offset };
    }
    log_poll_failed(error, position);
    TailInput::ReadFailed(error.to_string())
}

fn log_poll_failed(error: &PolicyLogTailError, position: i64) {
    tracing::warn!(%error, position, "the tail could not poll the state topic");
}

async fn apply(ports: &TailPorts, records: Vec<FramedRecord>) -> Result<TailInput, TailEnd> {
    match ports.applier.apply(records).await {
        ApplyResult::Applied => Ok(TailInput::Applied),
        ApplyResult::Fenced(cause) => Ok(TailInput::ApplyFenced(cause)),
        ApplyResult::Gone => Err(TailEnd::ApplierGone),
    }
}

/// The milliseconds since the epoch of `time`; zero for a clock before the epoch, which disables
/// the append-time check rather than fencing on a broken clock.
fn now_ms(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
