//! The driver of the bootstrap machine: it executes the actions against the state topic.

use iam_domain::{PolicyBootstrapLog, TAIL_READ_LIMIT};

use super::{
    BootstrapAction, BootstrapFailure, BootstrapInput, BootstrapMachine, BootstrapSnapshot,
};

/// How a bootstrap ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// The state to publish.
    Started(BootstrapSnapshot),
    /// The pod stays not started.
    NotStarted(BootstrapFailure),
}

/// What the actions of one step lead to.
enum Settled {
    Done(BootstrapOutcome),
    Next(BootstrapInput),
}

/// Runs `machine` against `log` until it publishes or gives up, then closes the connection.
pub async fn run_bootstrap(
    machine: BootstrapMachine,
    log: &dyn PolicyBootstrapLog,
) -> BootstrapOutcome {
    let outcome = drive(machine, log).await;
    log.close().await;
    outcome
}

async fn drive(mut machine: BootstrapMachine, log: &dyn PolicyBootstrapLog) -> BootstrapOutcome {
    let mut input = BootstrapInput::Start;
    loop {
        let (next, actions) = machine.step(input);
        machine = next;
        match settle(actions, log).await {
            Settled::Done(outcome) => return outcome,
            Settled::Next(following) => input = following,
        }
    }
}

async fn settle(actions: Vec<BootstrapAction>, log: &dyn PolicyBootstrapLog) -> Settled {
    let mut following = None;
    for action in actions {
        match action {
            BootstrapAction::Publish(snapshot) => {
                return Settled::Done(BootstrapOutcome::Started(snapshot));
            }
            BootstrapAction::NotStarted(failure) => {
                report_not_started(&failure);
                return Settled::Done(BootstrapOutcome::NotStarted(failure));
            }
            BootstrapAction::Retry(failure) => report_retry(&failure),
            BootstrapAction::CaptureStableEnd => following = Some(capture(log).await),
            BootstrapAction::Read { from, up_to } => following = Some(read(log, from, up_to).await),
        }
    }
    Settled::Next(following.unwrap_or_else(stalled))
}

/// A step that asks for nothing and does not end would loop for ever; it is a failed read.
fn stalled() -> BootstrapInput {
    BootstrapInput::ReadFailed("the bootstrap made no progress".to_owned())
}

async fn capture(log: &dyn PolicyBootstrapLog) -> BootstrapInput {
    match log.stable_end().await {
        Ok(end) => BootstrapInput::StableEnd(end),
        Err(error) => BootstrapInput::ReadFailed(error.to_string()),
    }
}

async fn read(log: &dyn PolicyBootstrapLog, from: i64, up_to: i64) -> BootstrapInput {
    match log.read_framed(from, up_to).await {
        Ok(records) if records.len() <= TAIL_READ_LIMIT => BootstrapInput::Records(records),
        Ok(_oversized) => BootstrapInput::ReadFailed("a read returned too many records".to_owned()),
        Err(error) => BootstrapInput::ReadFailed(error.to_string()),
    }
}

fn report_retry(failure: &BootstrapFailure) {
    tracing::error!(%failure, version = ?failure_version(failure), "the gateway bootstrap failed; it starts again once");
}

fn report_not_started(failure: &BootstrapFailure) {
    tracing::error!(%failure, version = ?failure_version(failure), "the gateway stays not started: the bootstrap failed twice");
}

/// The version a failure names, when it names one.
const fn failure_version(failure: &BootstrapFailure) -> Option<i64> {
    match failure {
        BootstrapFailure::VersionAboveHead { version }
        | BootstrapFailure::DigestMismatch { version, .. } => Some(*version),
        BootstrapFailure::UnreadableHead(_) | BootstrapFailure::ReadFailed(_) => None,
    }
}

#[cfg(test)]
mod tests;
